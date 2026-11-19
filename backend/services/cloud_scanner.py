"""Azure/GCP cloud scanning with provider SDKs"""
import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry
from celery import shared_task
from core.database import get_sync_db
from models.finding import FindingSeverity
from sqlalchemy.orm import Session


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


@dataclass
class CloudAsset:
    provider: CloudProvider
    asset_id: str
    asset_type: str
    name: str
    region: str
    properties: Dict[str, Any]
    tags: Dict[str, str]
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    security_groups: List[str] = None


class AzureScanner(BaseScanner):
    """Azure cloud asset discovery and vulnerability scanning"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "AzureScanner"
        self.version = "1.0.0"
        self.subscription_id = config.get('subscription_id') if config else None
        self.tenant_id = config.get('tenant_id') if config else None
        self.client_id = config.get('client_id') if config else None
        self.client_secret = config.get('client_secret') if config else None
    
    def validate_target(self, target: str) -> bool:
        """Target can be subscription ID or resource group"""
        return bool(target)
    
    async def _get_azure_token(self) -> str:
        """Get Azure access token using service principal"""
        import msal
        
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=self.client_secret,
        )
        
        result = app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
        return result.get('access_token')
    
    async def _list_resources(self, token: str, resource_type: str = None) -> List[Dict]:
        """List Azure resources"""
        import aiohttp
        
        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resources"
        params = {'api-version': '2021-04-01'}
        if resource_type:
            params['$filter'] = f"resourceType eq '{resource_type}'"
        
        headers = {'Authorization': f'Bearer {token}'}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params) as resp:
                data = await resp.json()
                return data.get('value', [])
    
    async def _get_virtual_machines(self, token: str) -> List[CloudAsset]:
        """Get Azure VMs"""
        resources = await self._list_resources(token, 'Microsoft.Compute/virtualMachines')
        assets = []
        
        for vm in resources:
            asset = CloudAsset(
                provider=CloudProvider.AZURE,
                asset_id=vm['id'],
                asset_type='virtual_machine',
                name=vm['name'],
                region=vm['location'],
                properties={
                    'vm_size': vm.get('properties', {}).get('hardwareProfile', {}).get('vmSize'),
                    'os_type': vm.get('properties', {}).get('storageProfile', {}).get('osDisk', {}).get('osType'),
                    'provisioning_state': vm.get('properties', {}).get('provisioningState'),
                },
                tags=vm.get('tags', {}),
            )
            assets.append(asset)
        
        return assets
    
    async def _get_storage_accounts(self, token: str) -> List[CloudAsset]:
        """Get Azure Storage Accounts"""
        resources = await self._list_resources(token, 'Microsoft.Storage/storageAccounts')
        assets = []
        
        for sa in resources:
            asset = CloudAsset(
                provider=CloudProvider.AZURE,
                asset_id=sa['id'],
                asset_type='storage_account',
                name=sa['name'],
                region=sa['location'],
                properties={
                    'sku': sa.get('sku', {}).get('name'),
                    'kind': sa.get('kind'),
                    'access_tier': sa.get('properties', {}).get('accessTier'),
                    'allow_blob_public_access': sa.get('properties', {}).get('allowBlobPublicAccess'),
                    'minimum_tls_version': sa.get('properties', {}).get('minimumTlsVersion'),
                },
                tags=sa.get('tags', {}),
            )
            assets.append(asset)
        
        return assets
    
    async def _get_network_security_groups(self, token: str) -> List[CloudAsset]:
        """Get Azure NSGs"""
        resources = await self._list_resources(token, 'Microsoft.Network/networkSecurityGroups')
        assets = []
        
        for nsg in resources:
            asset = CloudAsset(
                provider=CloudProvider.AZURE,
                asset_id=nsg['id'],
                asset_type='network_security_group',
                name=nsg['name'],
                region=nsg['location'],
                properties={
                    'rules': nsg.get('properties', {}).get('securityRules', []),
                },
                tags=nsg.get('tags', {}),
            )
            assets.append(asset)
        
        return assets
    
    async def _get_key_vaults(self, token: str) -> List[CloudAsset]:
        """Get Azure Key Vaults"""
        resources = await self._list_resources(token, 'Microsoft.KeyVault/vaults')
        assets = []
        
        for kv in resources:
            asset = CloudAsset(
                provider=CloudProvider.AZURE,
                asset_id=kv['id'],
                asset_type='key_vault',
                name=kv['name'],
                region=kv['location'],
                properties={
                    'vault_uri': kv.get('properties', {}).get('vaultUri'),
                    'tenant_id': kv.get('properties', {}).get('tenantId'),
                    'enable_rbac': kv.get('properties', {}).get('enableRbacAuthorization'),
                    'public_network_access': kv.get('properties', {}).get('publicNetworkAccess'),
                },
                tags=kv.get('tags', {}),
            )
            assets.append(asset)
        
        return assets
    
    async def _get_app_services(self, token: str) -> List[CloudAsset]:
        """Get Azure App Services"""
        resources = await self._list_resources(token, 'Microsoft.Web/sites')
        assets = []
        
        for app in resources:
            asset = CloudAsset(
                provider=CloudProvider.AZURE,
                asset_id=app['id'],
                asset_type='app_service',
                name=app['name'],
                region=app['location'],
                properties={
                    'kind': app.get('kind'),
                    'state': app.get('properties', {}).get('state'),
                    'https_only': app.get('properties', {}).get('httpsOnly'),
                    'min_tls_version': app.get('properties', {}).get('minTlsVersion'),
                },
                tags=app.get('tags', {}),
            )
            assets.append(asset)
        
        return assets
    
    async def _check_vm_vulnerabilities(self, vm: CloudAsset) -> List[ScanFinding]:
        """Check VM for common vulnerabilities"""
        findings = []
        
        # Check if VM has public IP
        if vm.public_ip:
            findings.append(ScanFinding(
                title=f"Azure VM '{vm.name}' has Public IP",
                description=f"Virtual Machine '{vm.name}' has a public IP address assigned",
                severity='medium',
                target_url=f"azure://{vm.asset_id}",
                evidence={
                    'resource_type': 'virtual_machine',
                    'resource_name': vm.name,
                    'public_ip': vm.public_ip,
                    'region': vm.region,
                },
                remediation="Remove public IP if not required, or restrict with NSG",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_vm_public_ip_{vm.name}",
                source_rule_id="azure-vm-public-ip",
                tags=["azure", "vm", "network", "public-ip"],
            ))
        
        # Check for outdated OS
        os_type = vm.properties.get('os_type', '').lower()
        if 'windows' in os_type and '2012' in os_type:
            findings.append(ScanFinding(
                title=f"Azure VM '{vm.name}' Running Outdated Windows",
                description=f"VM is running Windows Server 2012 which is end-of-life",
                severity='high',
                target_url=f"azure://{vm.asset_id}",
                evidence={
                    'resource_type': 'virtual_machine',
                    'resource_name': vm.name,
                    'os_type': vm.properties.get('os_type'),
                },
                remediation="Upgrade to supported Windows version",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_vm_outdated_os_{vm.name}",
                source_rule_id="azure-vm-outdated-os",
                tags=["azure", "vm", "os", "eol"],
            ))
        
        return findings
    
    async def _check_storage_account_vulnerabilities(self, sa: CloudAsset) -> List[ScanFinding]:
        """Check Storage Account for vulnerabilities"""
        findings = []
        
        # Public blob access
        if sa.properties.get('allow_blob_public_access'):
            findings.append(ScanFinding(
                title=f"Azure Storage Account '{sa.name}' Allows Public Blob Access",
                description="Storage account allows anonymous public read access to blobs",
                severity='high',
                target_url=f"azure://{sa.asset_id}",
                evidence={
                    'resource_type': 'storage_account',
                    'resource_name': sa.name,
                    'allow_blob_public_access': True,
                },
                remediation="Disable public blob access unless explicitly required",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_storage_public_blob_{sa.name}",
                source_rule_id="azure-storage-public-blob",
                tags=["azure", "storage", "data-exposure"],
            ))
        
        # TLS version
        min_tls = sa.properties.get('minimum_tls_version', 'TLS1_0')
        if min_tls in ['TLS1_0', 'TLS1_1']:
            findings.append(ScanFinding(
                title=f"Azure Storage Account '{sa.name}' Allows Weak TLS",
                description=f"Storage account allows TLS {min_tls} which is deprecated",
                severity='medium',
                target_url=f"azure://{sa.asset_id}",
                evidence={
                    'resource_type': 'storage_account',
                    'resource_name': sa.name,
                    'minimum_tls_version': min_tls,
                },
                remediation="Set minimum TLS version to TLS 1.2",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_storage_weak_tls_{sa.name}",
                source_rule_id="azure-storage-weak-tls",
                tags=["azure", "storage", "crypto"],
            ))
        
        return findings
    
    async def _check_nsg_vulnerabilities(self, nsg: CloudAsset) -> List[ScanFinding]:
        """Check NSG rules for vulnerabilities"""
        findings = []
        
        rules = nsg.properties.get('rules', [])
        for rule in rules:
            props = rule.get('properties', {})
            
            # Check for overly permissive rules
            if props.get('direction') == 'Inbound' and props.get('access') == 'Allow':
                dest_port = props.get('destinationPortRange', '')
                if dest_port in ['22', '3389', '445', '135', '139', '1433', '3306', '5432', '6379', '27017']:
                    source = props.get('sourceAddressPrefix', '')
                    if source in ['*', '0.0.0.0/0', 'Internet']:
                        findings.append(ScanFinding(
                            title=f"Azure NSG '{nsg.name}' Allows Public Access to Port {dest_port}",
                            description=f"NSG rule allows inbound access to sensitive port {dest_port} from anywhere",
                            severity='high',
                            target_url=f"azure://{nsg.asset_id}",
                            evidence={
                                'resource_type': 'network_security_group',
                                'resource_name': nsg.name,
                                'rule_name': rule.get('name'),
                                'port': dest_port,
                                'source': source,
                            },
                            remediation="Restrict source IP ranges for sensitive ports",
                            source_scanner="AzureScanner",
                            source_finding_id=f"azure_nsg_open_port_{nsg.name}_{dest_port}",
                            source_rule_id="azure-nsg-open-port",
                            tags=["azure", "network", "nsg", "open-port"],
                        ))
        
        return findings
    
    async def _check_key_vault_vulnerabilities(self, kv: CloudAsset) -> List[ScanFinding]:
        """Check Key Vault for vulnerabilities"""
        findings = []
        
        # Public network access
        if kv.properties.get('public_network_access') == 'Enabled':
            findings.append(ScanFinding(
                title=f"Azure Key Vault '{kv.name}' Has Public Network Access",
                description="Key Vault is accessible from public internet",
                severity='high',
                target_url=f"azure://{kv.asset_id}",
                evidence={
                    'resource_type': 'key_vault',
                    'resource_name': kv.name,
                    'public_network_access': True,
                },
                remediation="Disable public network access, use private endpoints",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_kv_public_access_{kv.name}",
                source_rule_id="azure-kv-public-access",
                tags=["azure", "keyvault", "secrets", "network"],
            ))
        
        # RBAC not enabled
        if not kv.properties.get('enable_rbac'):
            findings.append(ScanFinding(
                title=f"Azure Key Vault '{kv.name}' Not Using RBAC",
                description="Key Vault uses legacy access policies instead of Azure RBAC",
                severity='medium',
                target_url=f"azure://{kv.asset_id}",
                evidence={
                    'resource_type': 'key_vault',
                    'resource_name': kv.name,
                    'enable_rbac': False,
                },
                remediation="Enable Azure RBAC for Key Vault",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_kv_no_rbac_{kv.name}",
                source_rule_id="azure-kv-no-rbac",
                tags=["azure", "keyvault", "iam"],
            ))
        
        return findings
    
    async def _check_app_service_vulnerabilities(self, app: CloudAsset) -> List[ScanFinding]:
        """Check App Service for vulnerabilities"""
        findings = []
        
        # HTTPS only
        if not app.properties.get('https_only'):
            findings.append(ScanFinding(
                title=f"Azure App Service '{app.name}' Not HTTPS Only",
                description="App Service allows HTTP traffic",
                severity='medium',
                target_url=f"azure://{app.asset_id}",
                evidence={
                    'resource_type': 'app_service',
                    'resource_name': app.name,
                    'https_only': False,
                },
                remediation="Enable 'HTTPS Only' in App Service configuration",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_app_https_{app.name}",
                source_rule_id="azure-app-https-only",
                tags=["azure", "app-service", "tls"],
            ))
        
        # TLS version
        min_tls = app.properties.get('min_tls_version', '1.0')
        if min_tls in ['1.0', '1.1']:
            findings.append(ScanFinding(
                title=f"Azure App Service '{app.name}' Allows Weak TLS",
                description=f"App Service allows TLS {min_tls} which is deprecated",
                severity='medium',
                target_url=f"azure://{app.asset_id}",
                evidence={
                    'resource_type': 'app_service',
                    'resource_name': app.name,
                    'min_tls_version': min_tls,
                },
                remediation="Set minimum TLS version to 1.2",
                source_scanner="AzureScanner",
                source_finding_id=f"azure_app_tls_{app.name}",
                source_rule_id="azure-app-tls",
                tags=["azure", "app-service", "crypto"],
            ))
        
        return findings
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        all_findings = []
        
        try:
            # Get Azure token
            token = await self._get_azure_token()
            
            # Gather all resources
            all_assets = []
            
            # Fetch different resource types
            vms = await self._get_virtual_machines(token)
            all_assets.extend(vms)
            
            storage_accounts = await self._get_storage_accounts(token)
            all_assets.extend(storage_accounts)
            
            nsgs = await self._get_network_security_groups(token)
            all_assets.extend(nsgs)
            
            key_vaults = await self._get_key_vaults(token)
            all_assets.extend(key_vaults)
            
            app_services = await self._get_app_services(token)
            all_assets.extend(app_services)
            
            # Check vulnerabilities for each asset type
            for vm in vms:
                all_findings.extend(await self._check_vm_vulnerabilities(vm))
            
            for sa in storage_accounts:
                all_findings.extend(await self._check_storage_account_vulnerabilities(sa))
            
            for nsg in nsgs:
                all_findings.extend(await self._check_nsg_vulnerabilities(nsg))
            
            for kv in key_vaults:
                all_findings.extend(await self._check_key_vault_vulnerabilities(kv))
            
            for app in app_services:
                all_findings.extend(await self._check_app_service_vulnerabilities(app))
            
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                scanner_name=self.name,
                status='failed',
                error_message=str(e),
                started_at=started_at,
                completed_at=datetime.utcnow(),
            )
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status='completed',
            findings=all_findings,
            raw_output=f"Scanned {len(all_findings)} Azure resources, found {len(all_findings)} issues",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            metadata={
                'subscription_id': self.subscription_id,
                'resources_scanned': len(all_findings) if 'all_assets' in locals() else 0,
            },
        )


class GCPScanner(BaseScanner):
    """GCP cloud asset discovery and vulnerability scanning"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "GCPScanner"
        self.version = "1.0.0"
        self.project_id = config.get('project_id') if config else None
        self.credentials_path = config.get('credentials_path') if config else None
    
    def validate_target(self, target: str) -> bool:
        return bool(target)
    
    async def _get_gcp_client(self):
        """Get authenticated GCP client"""
        from google.cloud import compute_v1, storage, iam_v1
        from google.oauth2 import service_account
        
        if self.credentials_path:
            credentials = service_account.Credentials.from_service_account_file(
                self.credentials_path,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
        else:
            # Use default credentials
            import google.auth
            credentials, _ = google.auth.default(
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
        
        return credentials
    
    async def _get_compute_instances(self) -> List[Dict]:
        """Get GCP Compute Engine instances"""
        # Implementation would use google-cloud-compute
        return []
    
    async def _get_storage_buckets(self) -> List[Dict]:
        """Get GCP Cloud Storage buckets"""
        return []
    
    async def _get_firewall_rules(self) -> List[Dict]:
        """Get GCP VPC firewall rules"""
        return []
    
    async def _get_iam_policies(self) -> List[Dict]:
        """Get GCP IAM policies"""
        return []
    
    async def _check_gcp_vulnerabilities(self, resources: List[Dict]) -> List[ScanFinding]:
        """Check GCP resources for vulnerabilities"""
        findings = []
        
        for resource in resources:
            # Implementation for GCP-specific checks
            pass
        
        return findings
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        # GCP implementation would go here
        # For now, return empty result
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status='completed',
            findings=[],
            raw_output="GCP scanning not fully implemented yet",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            metadata={
                'project_id': self.project_id,
            },
        )


class CloudScanner(BaseScanner):
    """Unified cloud scanner for all providers"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "CloudScanner"
        self.version = "1.0.0"
        self.azure = AzureScanner(config.get('azure') if config else None)
        self.gcp = GCPScanner(config.get('gcp') if config else None)
    
    def validate_target(self, target: str) -> bool:
        return True
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        all_findings = []
        
        providers = options.get('providers', ['azure', 'gcp'])
        
        if 'azure' in providers:
            azure_result = await self.azure.scan(target, options.get('azure', {}))
            all_findings.extend(azure_result.findings)
        
        if 'gcp' in providers:
            gcp_result = await self.gcp.scan(target, options.get('gcp', {}))
            all_findings.extend(gcp_result.findings)
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status='completed',
            findings=all_findings,
            raw_output=f"Cloud scan found {len(all_findings)} issues",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            metadata={
                'providers': providers,
                'total_findings': len(all_findings),
            },
        )


# Register cloud scanners
ScannerRegistry.register(AzureScanner())
ScannerRegistry.register(GCPScanner())
ScannerRegistry.register(CloudScanner())


# Celery task
@shared_task(bind=True, max_retries=1)
def run_cloud_scan_task(self, scan_id: str, scan_config: dict):
    """Run cloud scan task"""
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
            
            scanner = CloudScanner()
            result = await scanner.scan(scan.target, {
                'scan_id': str(scan.id),
                'providers': scan_config.get('providers', ['azure']),
                'azure': scan_config.get('azure', {}),
                'gcp': scan_config.get('gcp', {}),
            })
            
            for finding_data in result.findings:
                finding = Finding(
                    workspace_id=scan.workspace_id,
                    scan_id=scan.id,
                    asset_id=scan.asset_id,
                    title=finding_data.title,
                    description=finding_data.description,
                    severity=FindingSeverity(finding_data.severity),
                    status=FindingStatus.OPEN,
                    target_url=finding_data.target_url,
                    parameter=finding_data.parameter,
                    evidence=finding_data.evidence,
                    reproduction_steps=finding_data.reproduction_steps,
                    proof_of_concept=finding_data.proof_of_concept,
                    remediation=finding_data.remediation,
                    references=finding_data.references,
                    fingerprint=f"cloud_{finding_data.source_finding_id}",
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