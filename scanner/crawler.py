import asyncio
import aiohttp
import hashlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, Dict, List


class AdvancedWebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages

        self.visited = set()
        self.successful_pages = set()
        self.visited_lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(5)

        self.pages_data = []
        self.forms = []
        self.inputs = []
        self.cookies = []

        self.headers = {}
        self.page_headers = {}
        self.technologies = set()

        self.form_hashes = set()
        self.input_hashes = set()
        self.cookie_hashes = set()

        self.browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    async def crawl(self) -> Dict:
        timeout = aiohttp.ClientTimeout(total=18)
        connector = aiohttp.TCPConnector(ssl=False, limit=15)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await self._crawl_recursive(self.base_url, session, depth=0)

        if len(self.pages_data) == 0:
            print("[CRAWLER] aiohttp blocked, using requests fallback")
            await self._requests_force_capture(self.base_url)

        return {
            'pages': self.pages_data,
            'forms': self.forms,
            'inputs': self.inputs,
            'cookies': self.cookies,
            'headers': self.headers,
            'page_headers': self.page_headers,
            'technologies': list(self.technologies),
            'total_pages': len(self.successful_pages)
        }

    async def _crawl_recursive(self, url: str, session: aiohttp.ClientSession, depth: int):
        if depth > self.max_depth:
            return
        if len(self.successful_pages) >= self.max_pages:
            return
        if not self._is_same_domain(url):
            return

        async with self.visited_lock:
            if url in self.visited:
                return
            self.visited.add(url)

        try:
            async with self.semaphore:
                async with session.get(url, headers=self.browser_headers, allow_redirects=True) as response:
                    print(f"[CRAWL] {url} -> {response.status}")

                    if response.status != 200:
                        return

                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type.lower():
                        return

                    html = await response.text(errors='ignore')
                    if len(html.strip()) < 200:
                        return

                    self.successful_pages.add(url)

                    current_headers = dict(response.headers)
                    self.headers.update(current_headers)
                    self.page_headers[url] = current_headers

                    page_data = await self._analyze_page(url, html, response)
                    self.pages_data.append(page_data)

                    links = self._extract_links(html, url)
                    for link in list(links)[:20]:
                        await self._crawl_recursive(link, session, depth + 1)

        except Exception as e:
            print(f"[ERROR] crawl fail {url}: {e}")

    async def _requests_force_capture(self, url: str):
        try:
            resp = requests.get(
                url,
                headers=self.browser_headers,
                timeout=20,
                verify=False,
                allow_redirects=True
            )

            print(f"[REQUESTS FALLBACK] {url} -> {resp.status_code}")

            if resp.status_code != 200:
                return

            html = resp.text
            if len(html.strip()) < 200:
                return

            class DummyResponse:
                headers = dict(resp.headers)
                cookies = []

            self.successful_pages.add(url)
            self.page_headers[url] = dict(resp.headers)

            page_data = await self._analyze_page(url, html, DummyResponse())
            self.pages_data.append(page_data)

        except Exception as e:
            print(f"[REQUESTS FALLBACK FAIL] {url}: {e}")

    async def _analyze_page(self, url: str, html: str, response) -> Dict:
        soup = BeautifulSoup(html, 'html.parser')

        forms = self._extract_forms(soup, url)
        for form in forms:
            sig = hashlib.md5(f"{form['action']}{form['method']}{str(form['inputs'])}".encode()).hexdigest()
            if sig not in self.form_hashes:
                self.form_hashes.add(sig)
                self.forms.append(form)

        inputs = self._extract_inputs(soup)
        for inp in inputs:
            sig = hashlib.md5(str(inp).encode()).hexdigest()
            if sig not in self.input_hashes:
                self.input_hashes.add(sig)
                self.inputs.append(inp)

        scripts = self._extract_scripts(soup)

        tech = self._detect_technologies(html, self.page_headers.get(url, {}))
        self.technologies.update(tech)

        return {
            'url': url,
            'title': soup.title.string.strip() if soup.title and soup.title.string else '',
            'forms_count': len(forms),
            'inputs_count': len(inputs),
            'scripts_count': len(scripts),
            'has_javascript': len(scripts) > 0,
            'external_resources': self._extract_external_resources(soup),
            'meta_tags': self._extract_meta_tags(soup),
            'security_headers': self._analyze_security_headers(self.page_headers.get(url, {}))
        }

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        forms_data = []
        for form in soup.find_all('form'):
            action_url = urljoin(base_url, form.get('action', ''))
            method = form.get('method', 'get').upper()

            inputs = []
            for field in form.find_all(['input', 'textarea', 'select', 'button']):
                inputs.append({
                    'name': field.get('name', ''),
                    'type': field.get('type', 'text'),
                    'value': field.get('value', ''),
                    'required': field.has_attr('required')
                })

            forms_data.append({
                'action': action_url,
                'method': method,
                'inputs': inputs,
                'has_csrf': self._has_csrf_token(form),
                'is_login': self._is_login_form(inputs)
            })
        return forms_data

    def _extract_inputs(self, soup: BeautifulSoup) -> List[Dict]:
        return [{
            'name': f.get('name', ''),
            'type': f.get('type', 'text'),
            'id': f.get('id', ''),
            'placeholder': f.get('placeholder', ''),
            'required': f.has_attr('required')
        } for f in soup.find_all(['input', 'textarea', 'select'])]

    def _extract_scripts(self, soup: BeautifulSoup) -> List[Dict]:
        return [{'src': s.get('src', ''), 'inline': bool(s.string or '')} for s in soup.find_all('script')]

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href')
            if href:
                full = urljoin(base_url, href).split('#')[0].rstrip('/')
                if self._is_valid_url(full) and self._is_same_domain(full):
                    links.add(full)
        return links

    def _extract_external_resources(self, soup: BeautifulSoup) -> List[str]:
        resources = []
        for tag in soup.find_all(['script', 'link', 'img']):
            src = tag.get('src') or tag.get('href')
            if src and not src.startswith(('data:', 'javascript:')):
                resources.append(src)
        return list(set(resources))

    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict:
        meta = {}
        for m in soup.find_all('meta'):
            name = m.get('name') or m.get('property', '')
            content = m.get('content', '')
            if name:
                meta[name] = content
        return meta

    def _analyze_security_headers(self, headers: Dict) -> Dict:
        sec = {
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Referrer-Policy': headers.get('Referrer-Policy')
        }
        missing = [k for k, v in sec.items() if not v]
        return {
            'present': {k: v for k, v in sec.items() if v},
            'missing': missing,
            'security_score': round(((6 - len(missing)) / 6) * 100, 2)
        }

    def _detect_technologies(self, html: str, headers: Dict) -> Set[str]:
        technologies = set()
        html_lower = html.lower()
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()

        if 'nginx' in server: technologies.add('Nginx')
        if 'apache' in server: technologies.add('Apache')
        if 'php' in powered: technologies.add('PHP')
        if 'asp.net' in powered: technologies.add('ASP.NET')
        if 'react' in html_lower: technologies.add('React')
        if 'vue' in html_lower: technologies.add('Vue.js')
        if 'angular' in html_lower: technologies.add('Angular')

        return technologies

    def _has_csrf_token(self, form) -> bool:
        for i in form.find_all('input'):
            if any(x in i.get('name', '').lower() for x in ['csrf', 'token', '_token']):
                return True
        return False

    def _is_login_form(self, inputs: List[Dict]) -> bool:
        has_password = any(i['type'] == 'password' for i in inputs)
        has_user = any(i['name'].lower() in ['username', 'email', 'user', 'login'] for i in inputs if i['name'])
        return has_password and has_user

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    def _is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.scheme in ['http', 'https']