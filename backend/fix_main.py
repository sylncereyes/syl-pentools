p='main.py'
s=open(p).read()
old = "            if \"tags\" in updates and isinstance(updates[\"tags\"], list):\n                finding.tags = updates[\"tags\"]\n\n        sys.stdout.flush()\n        await db.commit()\n        print(f\"DEBUG after commit\")\n        sys.stdout.flush()\n        # Re-query with relationships loaded for serialization\n        await db.commit()\n        print(f\"DEBUG after commit\")\n        sys.stdout.flush()\n        # Don't re-query with selectinload - just serialize without comments/attachments for bulk\n        # serialize_finding_detail will show empty lists for unloaded relationships\n        print(f\"DEBUG serializing without re-query...\")\n        sys.stdout.flush()\n        result = [serialize_finding_detail(f) for f in findings]\n        print(f\"DEBUG serialized: {len(result)}\")\n        sys.stdout.flush()\n\nroutes = ['']\n"

new = """            if "tags" in updates and isinstance(updates["tags"], list):
                finding.tags = updates["tags"]

        await db.commit()
        return JSONResponse([serialize_finding_detail(f) for f in findings])

routes = ['']"""

s = s.replace(old, new)
open(p,'w').write(s)
