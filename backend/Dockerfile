FROM node:18

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Expose backend port (example: 5000)
EXPOSE 5000

# Start backend server
CMD ["node", "server.js"]
