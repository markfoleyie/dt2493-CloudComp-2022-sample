FROM python:3.10

MAINTAINER Mark Foley

RUN apt -y update && apt -y upgrade

RUN mkdir -p /usr/src/app

COPY . /usr/src/app
WORKDIR /usr/src/app

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

#EXPOSE 5000
#CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

EXPOSE 5000
CMD ["uwsgi", "--ini", "uwsgi.ini"]