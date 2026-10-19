import os
import yaml

# Deliberately permissive demo configuration.
ALLOWED_ORIGINS = ["*"]
LOG_LEVEL = os.getenv("LOG_LEVEL", "debug")
SERVICE_ACCOUNT_JSON = '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----"}'

def load_config(path="config.yml"):
    with open(path, encoding="utf-8") as config:
        return yaml.load(config, Loader=yaml.Loader)

def run(command):
    os.system(command)
