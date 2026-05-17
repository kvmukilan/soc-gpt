.PHONY: up down pull-model run-ui test install

up:
	docker compose up -d

down:
	docker compose down

pull-model:
	docker compose exec ollama ollama pull llama3.2:3b

run-ui:
	streamlit run soc_gpt/ui/app.py

install:
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v
