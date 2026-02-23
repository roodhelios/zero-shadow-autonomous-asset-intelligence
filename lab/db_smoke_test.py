import psycopg2
from engine.utils.config import DB

def main():
    conn = psycopg2.connect(
        host=DB["host"],
        port=DB["port"],
        dbname=DB["name"],
        user=DB["user"],
        password=DB["password"],
    )
    cur = conn.cursor()
    cur.execute("SELECT now();")
    print("DB OK. now() =", cur.fetchone()[0])
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()