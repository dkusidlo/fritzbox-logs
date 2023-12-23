# FROM python:latest
FROM python:3.9-slim

WORKDIR /use/app/src

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY script.py ./

ENV url=$(FBURL)
ENV user=$(FBUSER)
ENV password=$(FBPASS)
ENV interval=$(FBINT)

CMD [ "/bin/sh", "-c", "python -u ./script.py ${url} ${user} ${password} ${interval}" ]
