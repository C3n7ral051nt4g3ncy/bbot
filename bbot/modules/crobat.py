from bbot.modules.base import BaseModule


class crobat(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by several other modules including sublist3r, dnsdumpster, etc.
    """

    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query Project Crobat for subdomains"}

    base_url = "https://sonar.omnisint.io"

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        """
        Accept DNS_NAMEs that are either directly targets, or indirectly
        in scope by resolving to in-scope IPs.

        Kill wildcards with fire.

        This filter_event is used across many modules
        """
        if any(t in event.tags for t in ("dns-error", "unresolved")):
            return False
        query = self.make_query(event)
        if self.already_processed(query):
            return False
        is_wildcard, _ = self.helpers.is_wildcard(f"{self.helpers.rand_string(digits=False)}.{query}")
        if is_wildcard:
            return False
        self.processed.add(hash(query))
        return True

    def already_processed(self, hostname):
        return any(
            hash(parent) in self.processed
            for parent in self.helpers.domain_parents(hostname, include_self=True)
        )

    def abort_if(self, event):
        # this helps weed out unwanted results when scanning IP_RANGES and wildcard domains
        return "in-scope" not in event.tags or "wildcard" in event.tags

    def handle_event(self, event):
        query = self.make_query(event)
        if results := self.query(query):
            for hostname in results:
                if hostname != event:
                    self.emit_event(hostname, "DNS_NAME", event, abort_if=self.abort_if)

    def request_url(self, query):
        url = f"{self.base_url}/subdomains/{self.helpers.quote(query)}"
        return self.helpers.request(url)

    def make_query(self, event):
        if "target" in event.tags:
            return str(event.data)
        else:
            return self.helpers.parent_domain(event.data).lower()

    def parse_results(self, r, query=None):
        if json := r.json():
            yield from json

    def query(self, query):
        try:
            if results := list(self.parse_results(self.request_url(query), query)):
                return results
            self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving results for {query}")
            self.debug(traceback.format_exc())
