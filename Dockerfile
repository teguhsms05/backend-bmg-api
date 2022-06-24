#Create a ubuntu base image with python 3 installed.
FROM python:3.9.7

#Set the working directory
WORKDIR /app

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /app
RUN pip install -r requirements.txt

# copy project
COPY . .

#Expose the required port
EXPOSE 5005

#Run the command
CMD gunicorn main:app