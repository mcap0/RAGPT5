# RAGPT5
RAGPT5 è un'implementazione a scopo didattico e di sperimentazione avversaria del framework [RAGent](https://arxiv.org/abs/2409.07489), da Matteo Capodicasa.

**R**etrieval-based **A**ccess control policy Generation using Chat **GPT5**)

Insert a series of statements and RAGPT5 will generate ACP in json format, ready to be converted in XACML or your AC Language of choice!

## Usage
```bash
cp .env.example .env   # insert KEY <- OPENAI
docker compose up --build
http://localhost:8000

# remember to insert the environment file <environment>.txt in the app/data folder (Default is universita.txt)
```
