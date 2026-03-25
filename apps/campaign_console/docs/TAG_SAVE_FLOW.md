# Where tags are saved to the database

## Flow when you click "Save changes" with tags

1. **Frontend** ([templates/add_customer.html](add_customer.html))  
   Form submit builds a payload with `tags: state.modalTagNames` (array of tag names) and sends  
   `PUT /api/customers/<id>?db_mode=...` with that JSON body.

2. **Backend** ([app.py](app.py) – `update_customer_api`)  
   - Finds the customer (with optional fallback to the other table if not found).  
   - Updates customer fields via `dbmod.update_customer(...)`.  
   - **Only if** `payload.get("tags")` is a **list**, it runs:
     ```python
     tag_names = payload.get("tags")
     if isinstance(tag_names, list):
         table = dbmod.get_customer_table_name()
         dbmod.set_customer_tags(table, cust_id, tag_names)  # <-- only DB write for tags
         row["tags"] = dbmod.get_customer_tags(table, cust_id)
     ```
   If the request returns **404 "Customer not found"** before this block, this code never runs, so nothing is written to `tags` or `customer_tags`.

3. **`set_customer_tags`** ([mailer/db.py](mailer/db.py))  
   - For each tag name in the list:
     - Calls **`get_or_create_tag(name)`**:
       - **`tags` table**: `SELECT` by name; if missing, **`INSERT INTO tags (name) VALUES (%s)`** (this is where the tag row is created).
       - Returns the tag `id`.
     - Collects all tag ids.
   - **`customer_tags` table**:  
     - `DELETE FROM customer_tags WHERE customer_table = %s AND custid = %s`  
     - Then for each tag id: **`INSERT INTO customer_tags (customer_table, custid, tag_id) VALUES (...)`**  
   So the **bridge table** is written only inside `set_customer_tags`.

## Summary: where each table is written

| Table           | Where it’s written | File:function / line (approx) |
|----------------|--------------------|--------------------------------|
| **tags**       | New tag row        | `mailer/db.py` → `get_or_create_tag()` → `INSERT INTO tags (name)` |
| **customer_tags** | Link customer ↔ tag | `mailer/db.py` → `set_customer_tags()` → `DELETE` then `INSERT` for that customer |

`set_customer_tags` is only called from `update_customer_api` when the customer has been found and updated and `payload["tags"]` is a list. If you never reach that (e.g. 404 earlier), neither table is updated.

## Tables must exist

Tag tables are created at **app startup** in [app.py](app.py) (around the end of the file):

```python
with app.app_context():
    dbmod.ensure_tag_tables()  # creates tags + customer_tags if not exist
```

If that fails (e.g. DB permissions), the `tags` and `customer_tags` tables may be missing and any later `INSERT` will fail.
