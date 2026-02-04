FROM nginx:alpine

# Copy custom HTML page for demo
COPY index.html /usr/share/nginx/html/

# Expose port
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
