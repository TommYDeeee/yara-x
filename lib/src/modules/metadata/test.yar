import "metadata"

rule test {
	condition:
		metadata.file.name("foo") == 2 and
		metadata.file.name(/^fo*$/) == 3 and
		metadata.detection.name("test123") == 6 and
		metadata.detection.name(/^test123$/) == 6 and
		metadata.detection.name("AntiVir", "test123") == 3 and
		metadata.detection.name("AntiVir", /^test123$/) == 3 and
		metadata.arpot.dll(/^test123$/) == 2 and
		metadata.arpot.process(/^test123$/) == 2 and
		metadata.idp.rule_name(/^test123$/) == 2 and
		metadata.source.url(/^test123$/) == 2 and
		metadata.parent_process.path(/^test123$/) == 2
}
