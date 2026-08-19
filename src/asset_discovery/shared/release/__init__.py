"""Release identity primitives shared by the console, the supervisor and CI.

Deliberately dependency-free (stdlib only, no SQLModel, no FastAPI): the vendor
console must stay liftable into its own repository and the supervisor is a thin
layer that ships inside a customer image, so the ONE rule both of them have to
agree on lives here rather than being written twice.
"""

from __future__ import annotations
