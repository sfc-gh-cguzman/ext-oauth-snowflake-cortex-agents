import os
import snowflake.connector as sc
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

conn_params = {
    'account': os.getenv('SNOWFLAKE_ACCOUNT'),
    'user': os.getenv('SNOWFLAKE_USER'),
    'authenticator': 'oauth',
    'token': os.getenv('ACCESS_TOKEN'),
    'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    'database': os.getenv('SNOWFLAKE_DATABASE'),
    'schema': os.getenv('SNOWFLAKE_SCHEMA')
}

ctx = sc.connect(**conn_params)
cs = ctx.cursor()

cs.execute("SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_DATABASE(), CURRENT_SCHEMA(), CURRENT_TIMESTAMP()")
result = cs.fetchone()
print(result)

ctx.close()
cs.close()