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

// Keep project AGP variants out without hiding external resolution failures.
assert source.contains('configuration.incoming.artifactView')
assert source.contains('view.componentFilter { component -> component instanceof ModuleComponentIdentifier }')
assert !source.contains('resolvedConfiguration.resolvedArtifacts')
assert !source.contains('lenient')
assert source.contains('result.allDependencies.collect')
println 'Maven-only artifact view keeps the full dependency graph and strict errors'

// Execute the actual view/filter fragment against a strict API-shaped fixture.
// This checks selection, not AGP runtime compatibility (the Android CI task does that).
def fragment = source.substring(source.indexOf('def mavenArtifacts ='), source.indexOf('mavenArtifacts.each'))
def loader = new GroovyClassLoader()
loader.parseClass('class ModuleComponentIdentifier {}')
def external = loader.loadClass('ModuleComponentIdentifier').newInstance()
def localProject = new Object()
def selected = null
def view = new Expando(componentFilter: { filter ->
    selected = [external, localProject].findAll { filter(it) }
})
def configuration = [incoming: new Expando(artifactView: { action ->
    action(view)
    [artifacts: [artifacts: selected]]
})]
def actual = new GroovyShell(loader, new Binding([configuration: configuration]))
    .evaluate(fragment + '\nmavenArtifacts')
assert actual == [external]
// A failure from the strict artifact view must escape, never become partial evidence.
configuration.incoming = new Expando(artifactView: { action ->
    action(view)
    throw new IllegalStateException('unresolved-external-fixture')
})
try {
    new GroovyShell(loader, new Binding([configuration: configuration])).evaluate(fragment + '\nmavenArtifacts')
    assert false: 'external resolution failure was hidden'
} catch (IllegalStateException expected) {
    assert expected.message == 'unresolved-external-fixture'
}
println 'Actual artifact view fragment excludes only project components and propagates failures'
