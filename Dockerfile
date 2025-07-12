FROM python:3.11-slim

# Installer les dépendances système (ajout de spamc ici 👇)
RUN apt-get update && \
    apt-get install -y spamassassin spamc build-essential && \
    apt-get clean

WORKDIR /code
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]