.PHONY: help install start test demo clean lint docker-build

help:
	@echo "SentinelAI — Multi-Agent Penetration Testing Platform"
	@echo "Usage:"
	@echo "  make install     Install Python dependencies in virtual environment"
	@echo "  make start       Start the FastAPI backend and integrated dashboard (Port 8000)"
	@echo "  make test        Execute automated pytest test suite"
	@echo "  make demo        Run standalone offline end-to-end multi-agent demonstration"
	@echo "  make clean       Remove cache, virtualenv, and temporary database files"

install:
	cd backend && pip install -r requirements.txt

start:
	cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	cd backend && pytest tests/ -v

demo:
	python run_demo.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f backend/sentinel_ai.db sentinel_demo_report.json sentinel_demo_report.html
