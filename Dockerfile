FROM python:3-slim

RUN adduser --disabled-password --gecos "" appuser

COPY --chown=appuser:appuser . /action

WORKDIR /action

USER appuser

RUN pip install --user -r requirements.txt

ENTRYPOINT ["python3"]
CMD ["/action/git2kandji.py"]
