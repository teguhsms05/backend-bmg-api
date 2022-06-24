FROM python:3.9.7

#Set the working directory
WORKDIR /app

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /app
RUN pip install -r requirements.txt

# copy project
COPY ./src .

#Expose the required port
EXPOSE 5000

#Run the command
CMD gunicorn main:app