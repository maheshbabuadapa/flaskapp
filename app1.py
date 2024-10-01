import os
import redis
import time

# Get Redis connection details from environment variables
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = os.getenv('REDIS_PORT', 6379)
redis_password = os.getenv('REDIS_PASSWORD', None)

# Create a Redis client
try:
    redis_client = redis.StrictRedis(
        host=redis_host,
        port=int(redis_port),
        password=redis_password,
        decode_responses=True
    )
    # Test the connection
    redis_client.ping()
    print("Connected to Redis with password authentication!")
except redis.ConnectionError as e:
    print(f"Could not connect to Redis: {e}")
    exit(1)

# Simple function to set and get a value from Redis
def redis_operations():
    try:
        # Set a key-value pair in Redis
        redis_client.set("example_key", "Hello from OpenShift!")

        # Get the value back
        value = redis_client.get("example_key")
        print(f"Retrieved value from Redis: {value}")
    except Exception as e:
        print(f"Error during Redis operation: {e}")

# Run Redis operations every few seconds to demonstrate the connection
if __name__ == "__main__":
    while True:
        redis_operations()
        time.sleep(10)
