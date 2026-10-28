// Execute the actual task body against a minimal Gradle-shaped fixture. No network.
import groovy.json.JsonSlurper

def source = new File(args[0]).canonicalFile
def temporary = java.nio.file.Files.createTempDirectory('peerloom-pom-binding-').toFile()
try {
    def loader = new GroovyClassLoader()
    loader.parseClass('package org.gradle.api.artifacts.component; class ModuleComponentIdentifier { String group; String module; String version }')
    loader.parseClass('package org.gradle.api.artifacts.result; class ResolvedDependencyResult {}')
    loader.parseClass('package org.gradle.api.artifacts.result; class ResolvedArtifactResult { File file }')
    loader.parseClass('package org.gradle.maven; class MavenModule {}')
    loader.parseClass('package org.gradle.maven; class MavenPomArtifact {}')
    loader.parseClass('class GradleException extends RuntimeException { GradleException(String m) { super(m) } }')
    def id = loader.loadClass('org.gradle.api.artifacts.component.ModuleComponentIdentifier')
        .newInstance(group: 'org.example', module: 'demo', version: '1.2.3')
    def pom = new File(temporary, 'demo.pom')
    def jar = new File(temporary, 'demo.jar')
    pom.text = '<project><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.3</version></project>'
    jar.bytes = [1, 2, 3] as byte[]
    def resolvedPom = loader.loadClass('org.gradle.api.artifacts.result.ResolvedArtifactResult').newInstance(file: pom)
    def query = new Expando()
    query.forComponents = { components -> assert components.size() == 1 && components[0] == id; query }
    query.withArtifacts = { module, artifact -> query }
    query.execute = { -> [resolvedComponents: [new Expando(id: id, getArtifacts: { type -> [resolvedPom] })]] }
    def configuration = [incoming: [resolutionResult: [allComponents: [[id: id]], allDependencies: []],
        artifactView: { action ->
            def view = new Expando(componentFilter: { filter -> assert filter(id); assert !filter(new Object()) })
            action(view)
            [artifacts: [artifacts: [[id: [componentIdentifier: id], file: jar]]]]
        }]]
    def actions = [:]
    def tasks = new Expando(register: { name, action ->
        def task = new Expando(doLast: { callback -> actions[name] = callback })
        action.delegate = task
        action.resolveStrategy = Closure.DELEGATE_FIRST
        action()
    })
    def offline = [offline: false]
    def root = [file: { path -> new File(source.parentFile.parentFile, path) },
        layout: [buildDirectory: [file: { name -> new Expando(get: { -> [asFile: new File(temporary, name)] }) }]]]
    def binding = new Binding([tasks: tasks, gradle: [startParameter: offline], rootProject: root,
        configurations: [getByName: { name -> configuration }],
        dependencies: [createArtifactResolutionQuery: { -> query }]])
    new GroovyShell(loader, binding).evaluate(source)
    actions.prepareMavenPomEvidence()
    assert new File(temporary, 'maven-pom-bindings.json').isFile()
    offline.offline = true
    actions.collectMavenEvidence()
    def output = new File(temporary, 'maven-evidence-input.json')
    def result = new JsonSlurper().parse(output)
    assert result.scopes.every { it.packages[0].binding.pom_sha256 == it.packages[0].pom.sha256 }
    output.delete()
    jar.bytes = [9, 8, 7] as byte[]
    try {
        actions.collectMavenEvidence()
        assert false: 'changed binary accepted'
    } catch (RuntimeException error) {
        assert error.message == 'RESOLVED_POM_OR_BINARY_CHANGED_SINCE_PREPARATION'
    }
    assert !output.exists()
    jar.bytes = [1, 2, 3] as byte[]
    pom.text = '<project><groupId>other</groupId><artifactId>demo</artifactId><version>1.2.3</version></project>'
    try {
        actions.collectMavenEvidence()
        assert false: 'wrong POM identity accepted'
    } catch (RuntimeException error) {
        assert error.message == 'POM_COORDINATE_MISMATCH'
    }
    assert !output.exists()
    query.execute = { -> [resolvedComponents: []] }
    try {
        actions.collectMavenEvidence()
        assert false: 'missing POM accepted'
    } catch (RuntimeException error) {
        assert error.message.startsWith('POM_REQUIRED_FOR_RESOLVED_COORDINATE: ')
    }
    try {
        actions.prepareMavenPomEvidence()
        assert false: 'online preparation accepted in offline phase'
    } catch (RuntimeException error) {
        assert error.message == 'POM preparation requires the normal online build phase'
    }
    offline.offline = false
    try {
        actions.collectMavenEvidence()
        assert false: 'offline collection performed online'
    } catch (RuntimeException error) {
        assert error.message.startsWith('Maven evidence requires --offline')
    }
    println 'Actual preparation/offline task bodies: exact module query, POM identity, binary substitution rejection PASS'
} finally {
    temporary.deleteDir()
}
