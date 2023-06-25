rule RedBoolean
{
	strings:
		$javascript_redirect = "document.location.href = url;"
		$meta_redirect = "<meta http-equiv=\"refresh\" content=\"0;url"
		$fake_domain1 = "https://www.capha-auditor.ru/"
		$fake_domain2 = "https://posholhahuybot.com/"
		$fake_domain3 = "https://brasileprofit.br/"
		$fake_domain4 = "https://leprikon.in/"
		$fake_domain5 = "https://www.tomaslide.life/"

	condition:
		all of them
}