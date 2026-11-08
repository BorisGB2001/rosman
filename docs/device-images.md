# Device images & notes

Each device card shows an image gallery (slider) and a free-text **Notes** field
for operators to leave context for colleagues (rack position, quirks, etc.).

## Model images

Default product images are served from `<DataDir>/models/<key>.svg` (not bundled
in the binary, so the set can grow without a rebuild). `<key>` is the device's
RouterOS model string reduced to lower-case letters and digits, e.g.:

| Model              | File                       |
|--------------------|----------------------------|
| `CRS328-24P-4S+`   | `models/crs32824p4s.svg`   |
| `CRS354-48P-4S+2Q+`| `models/crs35448p4s2q.svg` |
| `RB4011iGS+`       | `models/rb4011igs.svg`     |

Drop an `.svg`/`.png`/`.jpg` named by that key into the folder and it appears on
every device of that model. The vector stencils published by MikroTik
(Visio/SVG set) are a good source.

## Per-device images

Operators can also upload photos (e.g. the unit in the rack) from the device
card; these are stored in the DB (`device_images`) and shown in the same slider.
