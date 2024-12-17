FROM debian
RUN apt-get update && \
    apt-get install -y nginx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm /etcd/nginx/sites-enabled/default
COPY *.conf /etc/nginx/conf.d/
EXPOSE 80
CMD nginx -g 'daemon off;'