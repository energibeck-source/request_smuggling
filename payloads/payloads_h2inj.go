package payloads

type CRLFVariant struct {
	ID     string
	Target string
}

func H2CRLFVariants() []CRLFVariant {
	return []CRLFVariant{

		{ID: "method_value_inj", Target: ":method"},
		{ID: "path_value_inj", Target: ":path"},
		{ID: "authority_value_inj", Target: ":authority"},

		{ID: "host_value_inj", Target: "header:host"},
		{ID: "user_agent_value_inj", Target: "header:user-agent"},

		{ID: "header_name_crlf_injection", Target: "header_name:crlf"},
		{ID: "header_name_te_smuggling", Target: "header_name:te_smuggle"},
	}
}
