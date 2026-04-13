import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer()
    ]
)

def get_logger(name):
    return structlog.get_logger(name)

IBM_API_BASE_URL = "https://api.quantum-computing.ibm.com"
