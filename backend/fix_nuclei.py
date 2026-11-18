with open('services/nuclei_scanner.py', 'r') as f:
    content = f.read()

# Update the __init__ to read from settings if config not provided
old_init = """    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "NucleiScanner"
        self.version = "1.0.0"
        self.nuclei_path = config.get('nuclei_path', 'nuclei') if config else 'nuclei'
        self.templates_path = config.get('templates_path', '/opt/nuclei-templates') if config else '/opt/nuclei-templates'"""

new_init = """    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "NucleiScanner"
        self.version = "1.0.0"
        # Read from settings if config not provided
        if config:
            self.nuclei_path = config.get('nuclei_path', 'nuclei')
            self.templates_path = config.get('templates_path', '/opt/nuclei-templates')
        else:
            from core.config import settings
            self.nuclei_path = getattr(settings, 'NUCLEI_PATH', 'nuclei')
            self.templates_path = getattr(settings, 'NUCLEI_TEMPLATES_PATH', '/opt/nuclei-templates')"""

content = content.replace(old_init, new_init)

# Update the registration
old_reg = 'ScannerRegistry.register(NucleiScanner())'
new_reg = """# Register with config from settings
from core.config import settings
nuclei_config = {
    'nuclei_path': getattr(settings, 'NUCLEI_PATH', 'nuclei'),
    'templates_path': getattr(settings, 'NUCLEI_TEMPLATES_PATH', '/opt/nuclei-templates'),
}
ScannerRegistry.register(NucleiScanner(nuclei_config))"""

content = content.replace(old_reg, new_reg)

with open('services/nuclei_scanner.py', 'w') as f:
    f.write(content)

print("Fixed!")