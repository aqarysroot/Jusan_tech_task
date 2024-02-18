FROM python:3.9

WORKDIR /app
COPY ./requirements.txt /app
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY . /app
EXPOSE 8000

ENV MODULE_NAME="server"

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--reload"]
