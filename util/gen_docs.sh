#!/bin/sh

../godoc-static/godoc-static -link-index -destination docs -verbose github.com/wilhelmy/topologyd github.com/gosnmp/gosnmp

# «parameters» are a special syntax invented for topologyd to make godoc output
# more similar to traditional doc generators.
sed -i -Ee 's/«[^»]*»/<span class="parameter">\0<\/span>/g' $(grep -lR « docs/ | grep -v 'docs.zip')

cat >>docs/lib/style.css <<EOT
.parameter {
  font-family: Menlo, monospace;
  background: lightgray;
  color: blue;
}
EOT

rm docs/docs.zip
(cd docs; zip -rv docs.zip .)
