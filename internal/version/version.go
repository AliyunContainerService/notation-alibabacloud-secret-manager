package version

var (
	Version       = ""
	BuildMetadata = "unreleased"
)

func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "+" + BuildMetadata
}
