# skapi

The [Skapi](https://www.skapi.com) backend for Python: sign users in, keep their sessions, and read and write your project's database. Same API as [skapi-js](https://www.npmjs.com/package/skapi-js), in Python style.

```
pip install skapi
```

```python
from skapi import Skapi

skapi = Skapi("<Project ID>")  # from your project's Settings page on skapi.com

skapi.login("user@example.com", "password")
record = skapi.post_record({"title": "Hello"}, {"table": {"name": "posts", "access_group": "public"}})
posts = skapi.get_records({"table": {"name": "posts", "access_group": "public"}})
```

- No dependencies: Python 3.9 or later, standard library only.
- Sign-in uses the same SRP exchange as skapi-js: the password never leaves your machine.
- Two-step login with an authenticator app, file attachments, and every query form of skapi-js.
- Realtime messages between users, in groups or one to one.
- Optional encryption of private records before upload, compatible with skapi-js: `pip install "skapi[encryption]"`.

Documentation: https://py.skapi.com
