FROM debian:bullseye

RUN apt-get update && \
    apt-get install -y spamassassin spamc && \
    apt-get clean

EXPOSE 783

CMD ["spamd", "-i", "0.0.0.0", "-A", "127.0.0.1", "--port=783", "--max-children=2"]
