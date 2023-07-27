# safearchive

**This is not an officially supported Google product.**

Safe-by-construction libraries for processing `tar` and `zip` archives, to
replace unsafe alternatives like `archive/tar` and `archive/zip` that are at
risk of path traversal attacks. Besides crafted filename entries in the archive,
this library also protects from symbolic link attacks.

## Usage

These libraries are fully compatible with their golang core counterpart, so
switching to them is as easy as changing the library import at the top, no
further modifications are needed.

The built-in security measures can be turned on or off one by one. Only those
security checks are enabled by default that do not break existing setups.

You may enable the other features individually like this:

```
tr := tar.NewReader(buf)
tr.SetSecurityMode(tr.GetSecurityMode() | tar.SanitizeFileMode | tar.DropXattrs)
```

or

```
tr.SetSecurityMode(tar.MaximumSecurityMode)
```

You may opt out from a certain feature like this:

```
tr.SetSecurityMode(tr.GetSecurityMode() &^ tar.SanitizeFileMode)
```
