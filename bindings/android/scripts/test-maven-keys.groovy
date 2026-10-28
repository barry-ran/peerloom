// Run with the Gradle-pinned Groovy runtime; no dependency or network resolution.
def source = new File(args[0]).text
def coordinateLine = source.readLines().find { it.trim().startsWith('def coordinate =') }
def keyLine = source.readLines().find { it.trim().startsWith('def key =') }
assert coordinateLine != null && keyLine != null
def id = [group: 'org.example', module: 'demo', name: 'demo', version: '1.0.0']
def coordinate = new GroovyShell().evaluate(coordinateLine + '\ncoordinate')
def key = new GroovyShell(new Binding([id: id])).evaluate(keyLine + '\nkey')
def records = [(coordinate(id)): [artifacts: [], pom: null]]
assert key instanceof String
assert records.keySet().every { it instanceof String }
assert records.containsKey(key)
records.get(key).artifacts.add('archive')
records.get(coordinate(id)).pom = 'pom'
assert records[key].artifacts == ['archive']
assert records[coordinate(id)].pom == 'pom'
println 'Maven actual coordinate/key artifact and POM lookup regression passed'
