FROM python:3-slim
COPY . /action
WORKDIR /action
RUN pip install --root-user-action=ignore -r requirements.txt
ENTRYPOINT ["python3"]
CMD ["/action/git2kandji.py"]