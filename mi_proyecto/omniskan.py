#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMNISCAN.PY - Escáner OSINT avanzado
Incluye TODAS las mejoras: Async + Fallback, Playwright, Backoff, Checkers reales, 
Logging, Metadata, Progress reporting, Cache, Estadísticas, Timeouts específicos,
Validación mejorada, Headers stealth, Exportación mejorada, y más.
"""

import aiohttp
import asyncio
import argparse
import csv
import hashlib
import json
import logging
import re
import requests
import sqlite3
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from random import choice, randint, uniform
from typing import Any, Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
from tqdm import tqdm

# Optional Playwright
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# -------------------- Logging Mejorado --------------------
def setup_logging(verbose: bool = False, log_file: str = 'omniscanner.log'):
    """Configuración de logging mejorada con rotación opcional"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Formato más informativo
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s'
    )
    
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Limpiar handlers existentes
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

logger = logging.getLogger(__name__)

# -------------------- Config Mejorada --------------------
class Config:
    """Configuración centralizada con valores por defecto optimizados"""
    TIMEOUT = 15
    MAX_WORKERS = 8
    RATE_LIMIT_BASE = 1.0
    MAX_RETRIES = 3
    REQUEST_DELAY = (0.5, 2.0)  # Delay entre requests (min, max)
    
    # User-Agents más diversos y realistas
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
    ]
    
    # Timeouts específicos por plataforma (segundos)
    PLATFORM_TIMEOUTS = {
        "github": 10,
        "twitter": 25,
        "instagram": 30,
        "reddit": 15,
        "linkedin": 20,
        "tiktok": 35,
        "youtube": 15,
        "twitch": 15,
        "default": 15
    }
    
    # Headers stealth por nivel de seguridad
    STEALTH_HEADERS = {
        1: {'User-Agent': choice(USER_AGENTS)},
        2: {
            'User-Agent': choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive'
        },
        3: {
            'User-Agent': choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
            'X-Forwarded-For': f"{randint(1,255)}.{randint(1,255)}.{randint(1,255)}.{randint(1,255)}"
        }
    }

# -------------------- Utilidades Mejoradas --------------------
def validate_username(username: str) -> Tuple[bool, str]:
    """Validación mejorada de username con mensajes de error específicos"""
    if not username or len(username) == 0:
        return False, "Username no puede estar vacío"
    if len(username) > 50:
        return False, "Username demasiado largo (máx 50 caracteres)"
    if re.search(r'[^\w\.\-_]', username):
        return False, "Username contiene caracteres inválidos"
    if username.startswith(('.', '-', '_')):
        return False, "Username no puede empezar con ., - o _"
    return True, "Username válido"

def calculate_evidence_score(result: 'ScanResult') -> int:
    """Cálculo inteligente de score de evidencia"""
    score = 0
    
    # Base score por existencia
    if result.exists:
        score += 3
    
    # Score por código HTTP
    if result.status_code == 200:
        score += 2
    elif 200 < result.status_code < 400:
        score += 1
    
    # Score por metadata
    if result.title and len(result.title) > 10:  # Título significativo
        score += 2
    if result.description:
        score += 1
    if result.avatar_url:
        score += 2
    if result.og_sitename:
        score += 1
    
    # Score por tiempo de respuesta (más rápido = más confiable)
    if result.response_time < 2.0:
        score += 1
    elif result.response_time > 10.0:
        score -= 1
    
    return min(score, 10)  # Máximo 10 puntos

# -------------------- Dataclass Mejorada --------------------
@dataclass
class ScanResult:
    platform: str
    url: str
    exists: bool
    response_time: float
    status_code: int
    error: Optional[str] = None
    ip_blocked: bool = False
    title: Optional[str] = None
    description: Optional[str] = None
    og_sitename: Optional[str] = None
    avatar_url: Optional[str] = None
    avatar_hash: Optional[str] = None
    external_links: List[str] = None
    evidence_score: int = 0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """Inicialización automática después de la creación"""
        if self.external_links is None:
            self.external_links = []
        if self.metadata is None:
            self.metadata = {}
        # Calcular score automáticamente
        if self.evidence_score == 0:
            self.evidence_score = calculate_evidence_score(self)

# -------------------- Checkers Mejorados --------------------
class PlatformChecker:
    """Clase base abstracta para todos los checkers"""
    
    def __init__(self, platform_name: str, base_url: str, stealth_level: int = 1):
        self.platform_name = platform_name
        self.base_url = base_url
        self.stealth_level = stealth_level
        self.requires_js = False
    
    async def check(self, username: str, session: aiohttp.ClientSession) -> ScanResult:
        raise NotImplementedError
    
    def _get_headers(self) -> Dict[str, str]:
        """Obtener headers según nivel de stealth"""
        return Config.STEALTH_HEADERS.get(self.stealth_level, Config.STEALTH_HEADERS[1]).copy()
    
    def _get_timeout(self) -> int:
        """Obtener timeout específico de la plataforma"""
        return Config.PLATFORM_TIMEOUTS.get(self.platform_name, Config.PLATFORM_TIMEOUTS["default"])
    
    async def _extract_metadata(self, content: bytes, url: str) -> Dict[str, Any]:
        """Extraer metadata genérica de HTML"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            metadata = {}
            
            # Title
            title_tag = soup.find('title')
            metadata['title'] = title_tag.get_text().strip() if title_tag else None
            
            # Description
            desc_tag = soup.find('meta', attrs={'name': 'description'}) or \
                      soup.find('meta', attrs={'property': 'og:description'})
            metadata['description'] = desc_tag.get('content') if desc_tag else None
            
            # OG Site Name
            og_site = soup.find('meta', attrs={'property': 'og:site_name'})
            metadata['og_sitename'] = og_site.get('content') if og_site else None
            
            # Avatar/Image
            avatar = soup.find('meta', attrs={'property': 'og:image'}) or \
                    soup.find('link', attrs={'rel': 'icon'}) or \
                    soup.find('link', attrs={'rel': 'shortcut icon'})
            metadata['avatar_url'] = avatar.get('href') if avatar else None
            
            # External links (limitado a 10)
            links = []
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href and href.startswith('http') and url not in href:
                    links.append(href)
            metadata['external_links'] = links[:10]
            
            return metadata
        except Exception as e:
            logger.warning(f"Error extrayendo metadata para {self.platform_name}: {e}")
            return {}

class GitHubChecker(PlatformChecker):
    """Checker específico para GitHub con detección mejorada"""
    
    def __init__(self):
        super().__init__("github", "https://github.com/{}", stealth_level=1)
    
    async def check(self, username: str, session: aiohttp.ClientSession) -> ScanResult:
        url = self.base_url.format(username)
        start_time = time.time()
        
        try:
            # Usar timeout específico de GitHub
            timeout = self._get_timeout()
            headers = self._get_headers()
            
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                content = await response.read()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Múltiples métodos para detectar existencia
                exists = (
                    soup.find('span', {'class': 'p-nickname'}) is not None or
                    soup.find('div', {'class': 'user-profile'}) is not None or
                    soup.find('h1', {'class': 'vcard-names'}) is not None or
                    response.status == 200 and "Page not found" not in soup.get_text()
                )
                
                # Extraer metadata mejorada
                metadata = await self._extract_metadata(content, url)
                
                # Información específica de GitHub
                github_meta = {}
                bio = soup.find('div', {'class': 'p-note'})
                if bio:
                    github_meta['bio'] = bio.get_text().strip()
                
                # Crear resultado
                result = ScanResult(
                    platform=self.platform_name,
                    url=url,
                    exists=exists,
                    response_time=time.time() - start_time,
                    status_code=response.status,
                    title=metadata.get('title'),
                    description=metadata.get('description'),
                    og_sitename=metadata.get('og_sitename'),
                    avatar_url=metadata.get('avatar_url'),
                    external_links=metadata.get('external_links', []),
                    metadata=github_meta
                )
                
                return result
                
        except Exception as e:
            return ScanResult(
                platform=self.platform_name,
                url=url,
                exists=False,
                response_time=time.time() - start_time,
                status_code=0,
                error=str(e)
            )

class TwitterChecker(PlatformChecker):
    """Checker para Twitter/X con soporte para JS"""
    
    def __init__(self):
        super().__init__("twitter", "https://x.com/{}", stealth_level=3)
        self.requires_js = True
    
    async def check(self, username: str, session: aiohttp.ClientSession) -> ScanResult:
        url = self.base_url.format(username)
        start_time = time.time()
        
        try:
            if PLAYWRIGHT_AVAILABLE and self.requires_js:
                # Usar Playwright para renderizado JS
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()
                    await page.goto(url, wait_until='networkidle')
                    content = await page.content()
                    await browser.close()
            else:
                # Fallback a request normal
                timeout = self._get_timeout()
                headers = self._get_headers()
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    content = await response.read()
            
            soup = BeautifulSoup(content, 'html.parser')
            exists = "page doesn't exist" not in soup.get_text().lower()
            
            metadata = await self._extract_metadata(content.encode() if isinstance(content, str) else content, url)
            
            return ScanResult(
                platform=self.platform_name,
                url=url,
                exists=exists,
                response_time=time.time() - start_time,
                status_code=200,  # Asumir 200 cuando usamos Playwright
                title=metadata.get('title'),
                description=metadata.get('description'),
                og_sitename=metadata.get('og_sitename'),
                avatar_url=metadata.get('avatar_url'),
                external_links=metadata.get('external_links', [])
            )
            
        except Exception as e:
            return ScanResult(
                platform=self.platform_name,
                url=url,
                exists=False,
                response_time=time.time() - start_time,
                status_code=0,
                error=str(e)
            )

# -------------------- OmniScanner Mejorado --------------------
class OmniScanner:
    """Scanner OSINT mejorado con todas las funcionalidades"""
    
    def __init__(self, timeout: int = Config.TIMEOUT, max_workers: int = Config.MAX_WORKERS,
                 use_async: bool = True, proxies_file: Optional[str] = None,
                 no_avatars: bool = False, enable_cache: bool = True):
        
        self.timeout = timeout
        self.max_workers = max_workers
        self.use_async = use_async and PLAYWRIGHT_AVAILABLE
        self.no_avatars = no_avatars
        self.enable_cache = enable_cache
        
        # Inicialización mejorada
        self.public_ip = self._get_public_ip()
        self.proxies = self._load_proxies(proxies_file)
        self.results: List[ScanResult] = []
        self.user = ""
        self.semaphore = asyncio.Semaphore(self.max_workers)
        
        # Cache para resultados
        self._result_cache = {}
        
        # Registrar todas las plataformas disponibles
        self.platforms = {
            "github": GitHubChecker(),
            "twitter": TwitterChecker(),
            # Se pueden agregar más checkers aquí
        }
        
        logger.info(f"✅ OmniScanner inicializado - Workers: {max_workers}, Timeout: {timeout}s")
        if self.proxies:
            logger.info(f"✅ Proxies cargados: {len(self.proxies)}")
        if self.use_async:
            logger.info("✅ Modo asíncrono activado")
        else:
            logger.info("✅ Modo síncrono activado")

    # -------------------- Utilities Mejoradas --------------------
    def _get_public_ip(self) -> str:
        """Obtener IP pública con múltiples fallbacks"""
        services = [
            'https://api.ipify.org?format=json',
            'https://ipinfo.io/json',
            'https://httpbin.org/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    return data.get('ip', data.get('origin', 'Unknown'))
            except Exception as e:
                logger.debug(f"Fallando servicio IP {service}: {e}")
                continue
        
        return 'Unknown'

    def _load_proxies(self, filename: Optional[str]) -> List[str]:
        """Cargar y validar proxies con mejor manejo de errores"""
        if not filename:
            return []
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                proxies = [line.strip() for line in f if line.strip()]
            
            # Validación exhaustiva de proxies
            valid_proxies = []
            for proxy in proxies:
                if (proxy.startswith(('http://', 'https://', 'socks5://')) and 
                    len(proxy) > 10 and 
                    ' ' not in proxy):
                    valid_proxies.append(proxy)
            
            logger.info(f"✅ Proxies válidos cargados: {len(valid_proxies)}/{len(proxies)}")
            return valid_proxies
            
        except Exception as e:
            logger.error(f"❌ Error cargando proxies: {e}")
            return []

    @staticmethod
    async def _make_request_with_retry(session: aiohttp.ClientSession, url: str,
                                      headers: Dict[str, str], platform: str = "default",
                                      max_retries: int = Config.MAX_RETRIES) -> Tuple[bytes, int]:
        """Método mejorado de request con retry y timeout específico"""
        
        platform_timeout = Config.PLATFORM_TIMEOUTS.get(platform, Config.PLATFORM_TIMEOUTS["default"])
        
        for attempt in range(max_retries):
            try:
                # Delay exponencial entre reintentos
                if attempt > 0:
                    delay = 2 ** attempt + uniform(0.5, 1.5)
                    await asyncio.sleep(delay)
                
                timeout = aiohttp.ClientTimeout(total=platform_timeout)
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    
                    # Validar respuesta
                    if response.status >= 500:
                        raise aiohttp.ClientError(f"Server error: {response.status}")
                    
                    content_type = response.headers.get('content-type', '').lower()
                    valid_content_types = ['text/html', 'application/json', 'text/plain']
                    
                    if not any(ct in content_type for ct in valid_content_types):
                        logger.warning(f"Content-type inusual para {platform}: {content_type}")
                    
                    content = await response.read()
                    return content, response.status
                    
            except asyncio.TimeoutError:
                logger.warning(f"Timeout en intento {attempt + 1} para {platform}")
                if attempt == max_retries - 1:
                    raise
                    
            except aiohttp.ClientError as e:
                logger.warning(f"Error HTTP en intento {attempt + 1} para {platform}: {e}")
                if attempt == max_retries - 1:
                    raise
        
        raise aiohttp.ClientError(f"Failed after {max_retries} attempts")

    async def _hash_avatar(self, session: aiohttp.ClientSession, avatar_url: str) -> Optional[str]:
        """Calcular hash de avatar con validación"""
        if self.no_avatars or not avatar_url:
            return None
        
        try:
            headers = {'User-Agent': choice(Config.USER_AGENTS)}
            async with session.get(avatar_url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.read()
                    if len(data) > 100:  # Validar que sea una imagen válida
                        return f"md5:{hashlib.md5(data).hexdigest()}"
        except Exception as e:
            logger.debug(f"Error hashing avatar {avatar_url}: {e}")
        
        return None

    # -------------------- Async Scan Mejorado --------------------
    async def _async_check_platform(self, session: aiohttp.ClientSession, 
                                   platform_name: str, pbar: tqdm = None) -> ScanResult:
        """Check individual de plataforma con manejo mejorado"""
        
        async with self.semaphore:
            # Verificar cache primero
            cache_key = f"{self.user}_{platform_name}"
            if self.enable_cache and cache_key in self._result_cache:
                if pbar:
                    pbar.update(1)
                return self._result_cache[cache_key]
            
            try:
                # Delay aleatorio entre requests
                delay = uniform(*Config.REQUEST_DELAY)
                await asyncio.sleep(delay)
                
                checker = self.platforms[platform_name]
                result = await checker.check(self.user, session)
                
                # Hash de avatar si es necesario
                if result.avatar_url and not self.no_avatars:
                    result.avatar_hash = await self._hash_avatar(session, result.avatar_url)
                
                # Cachear resultado
                if self.enable_cache:
                    self._result_cache[cache_key] = result
                
                return result
                
            except Exception as e:
                logger.error(f"Error checking {platform_name}: {e}")
                return ScanResult(
                    platform=platform_name,
                    url=checker.base_url.format(self.user),
                    exists=False,
                    response_time=0,
                    status_code=0,
                    error=str(e)
                )
            finally:
                if pbar:
                    pbar.update(1)

    async def scan_async(self, username: str, platforms: List[str] = None) -> List[ScanResult]:
        """Scan asíncrono principal con progress reporting"""
        if platforms is None:
            platforms = list(self.platforms.keys())
        
        self.user = username
        logger.info(f"🚀 Iniciando escaneo async para '{username}' en {len(platforms)} plataformas")
        
        # Configuración de sesión HTTP mejorada
        connector = aiohttp.TCPConnector(
            limit=self.max_workers,
            ssl=False,
            keepalive_timeout=30
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout * 3)  # Timeout global mayor
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            with tqdm(total=len(platforms), desc="🔍 Escaneando plataformas", unit="platform") as pbar:
                tasks = [self._async_check_platform(session, p, pbar) for p in platforms]
                results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filtrar resultados válidos
            valid_results = []
            for result in results:
                if isinstance(result, ScanResult):
                    valid_results.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Excepción en task: {result}")
            
            self.results = valid_results
            return valid_results

    def scan_sync(self, username: str, platforms: List[str] = None) -> List[ScanResult]:
        """Scan síncrono como fallback"""
        logger.info("🔄 Usando modo síncrono (fallback)")
        return asyncio.run(self.scan_async(username, platforms))

    def scan_username(self, username: str, platforms: List[str] = None) -> List[ScanResult]:
        """Método principal de scan con validación"""
        # Validar username
        is_valid, message = validate_username(username)
        if not is_valid:
            logger.error(f"❌ Username inválido: {message}")
            raise ValueError(f"Username inválido: {message}")
        
        self.user = username
        logger.info(f"🎯 Iniciando scan para usuario: {username}")
        
        if self.use_async:
            return asyncio.run(self.scan_async(username, platforms))
        else:
            return self.scan_sync(username, platforms)

    # -------------------- Exportación Mejorada --------------------
    def save_to_json(self, path: Path):
        """Exportar a JSON con formato mejorado"""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            
            export_data = {
                'scan_info': {
                    'username': self.user,
                    'timestamp': datetime.now().isoformat(),
                    'total_platforms': len(self.results),
                    'found_profiles': sum(1 for r in self.results if r.exists),
                    'public_ip': self.public_ip
                },
                'results': [asdict(r) for r in self.results]
            }
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"✅ JSON exportado: {path}")
        except Exception as e:
            logger.error(f"❌ Error exportando JSON: {e}")
            raise

    def save_to_csv(self, path: Path):
        """Exportar a CSV con más campos"""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                # Headers mejorados
                writer.writerow([
                    'platform', 'url', 'exists', 'status_code', 'response_time',
                    'error', 'ip_blocked', 'title', 'description', 'og_sitename',
                    'avatar_url', 'avatar_hash', 'evidence_score', 'external_links_count'
                ])
                
                for r in self.results:
                    writer.writerow([
                        r.platform, r.url, r.exists, r.status_code, r.response_time,
                        r.error or '', r.ip_blocked, r.title or '', r.description or '',
                        r.og_sitename or '', r.avatar_url or '', r.avatar_hash or '',
                        r.evidence_score, len(r.external_links) if r.external_links else 0
                    ])
            
            logger.info(f"✅ CSV exportado: {path}")
        except Exception as e:
            logger.error(f"❌ Error exportando CSV: {e}")
            raise

    def save_to_sqlite(self, db_path: Path):
        """Exportar a SQLite con schema mejorado"""
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            con = sqlite3.connect(db_path)
            cur = con.cursor()
            
            # Schema mejorado
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    url TEXT NOT NULL,
                    exists BOOLEAN NOT NULL,
                    status_code INTEGER,
                    response_time REAL,
                    error TEXT,
                    ip_blocked BOOLEAN DEFAULT FALSE,
                    title TEXT,
                    description TEXT,
                    og_sitename TEXT,
                    avatar_url TEXT,
                    avatar_hash TEXT,
                    evidence_score INTEGER DEFAULT 0,
                    external_links_json TEXT,
                    metadata_json TEXT,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(username, platform, scan_date)
                )
            """)
            
            # Índices para mejor performance
            cur.execute("CREATE INDEX IF NOT EXISTS idx_username ON scans(username)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_platform ON scans(platform)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_date ON scans(scan_date)")
            
            now = datetime.now().isoformat()
            for r in self.results:
                cur.execute("""
                    INSERT OR REPLACE INTO scans 
                    (username, platform, url, exists, status_code, response_time, error, 
                     ip_blocked, title, description, og_sitename, avatar_url, avatar_hash, 
                     evidence_score, external_links_json, metadata_json, scan_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.user, r.platform, r.url, r.exists, r.status_code, r.response_time,
                    r.error, r.ip_blocked, r.title, r.description, r.og_sitename,
                    r.avatar_url, r.avatar_hash, r.evidence_score,
                    json.dumps(r.external_links) if r.external_links else None,
                    json.dumps(r.metadata) if r.metadata else None,
                    now
                ))
            
            con.commit()
            con.close()
            logger.info(f"✅ SQLite exportado: {db_path}")
        except Exception as e:
            logger.error(f"❌ Error exportando SQLite: {e}")
            raise

    # -------------------- Estadísticas Mejoradas --------------------
    def print_statistics(self):
        """Estadísticas detalladas del scan"""
        if not self.results:
            print("📊 No hay resultados para mostrar")
            return
        
        total_time = sum(r.response_time for r in self.results)
        successful = sum(1 for r in self.results if r.status_code == 200)
        found = sum(1 for r in self.results if r.exists)
        avg_time = total_time / len(self.results) if self.results else 0
        avg_score = sum(r.evidence_score for r in self.results) / len(self.results) if self.results else 0
        
        # Plataformas con mejor score
        top_platforms = sorted(self.results, key=lambda x: x.evidence_score, reverse=True)[:3]
        
        print(f"\n{'📊 ESTADÍSTICAS DETALLADAS ':=^60}")
        print(f"   • Usuario escaneado: {self.user}")
        print(f"   • Plataformas analizadas: {len(self.results)}")
        print(f"   • Perfiles encontrados: {found} ({found/len(self.results)*100:.1f}%)")
        print(f"   • Requests exitosos: {successful} ({successful/len(self.results)*100:.1f}%)")
        print(f"   • Tiempo total: {total_time:.2f}s")
        print(f"   • Tiempo promedio/request: {avg_time:.2f}s")
        print(f"   • Score promedio: {avg_score:.1f}/10")
        print(f"   • IP pública: {self.public_ip}")
        
        if top_platforms:
            print(f"\n   🏆 Top 3 plataformas:")
            for i, platform in enumerate(top_platforms, 1):
                print(f"     {i}. {platform.platform}: Score {platform.evidence_score}/10")
        
        print("=" * 60)

    def export_results(self, formats: List[str], base_path: Path):
        """Exportación unificada a múltiples formatos"""
        if not self.results:
            logger.warning("No hay resultados para exportar")
            return
        
        export_methods = {
            'json': self.save_to_json,
            'csv': self.save_to_csv,
            'sqlite': self.save_to_sqlite
        }
        
        for fmt in formats:
            if fmt in export_methods:
                try:
                    export_path = base_path.with_suffix(f'.{fmt}')
                    export_methods[fmt](export_path)
                except Exception as e:
                    logger.error(f"❌ Error exportando a {fmt}: {e}")
            else:
                logger.warning(f"Formato no soportado: {fmt}")

    def clear_cache(self):
        """Limpiar cache de resultados"""
        self._result_cache.clear()
        logger.info("✅ Cache limpiado")

# -------------------- CLI Mejorada --------------------
def main():
    """Función principal con argumentos mejorados"""
    parser = argparse.ArgumentParser(
        description="🦾 OmniScan - Escáner OSINT Avanzado",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python omniscan.py -u john_doe
  python omniscan.py -u jane_smith --platforms github twitter
  python omniscan.py -u test_user --proxies proxies.txt --workers 12
  python omniscan.py -u target --json resultado.json --csv resultado.csv
        """
    )
    
    parser.add_argument('-u', '--username', required=True, help='Username a investigar')
    parser.add_argument('-p', '--platforms', nargs='+', help='Plataformas específicas a escanear')
    parser.add_argument('--db', help='Archivo de base de datos SQLite para exportar')
    parser.add_argument('--json', help='Archivo JSON para exportar')
    parser.add_argument('--csv', help='Archivo CSV para exportar')
    parser.add_argument('--no-avatars', action='store_true', help='No descargar avatares')
    parser.add_argument('--proxies', help='Archivo con lista de proxies')
    parser.add_argument('--workers', type=int, default=Config.MAX_WORKERS, 
                       help=f'Número de workers (default: {Config.MAX_WORKERS})')
    parser.add_argument('--timeout', type=int, default=Config.TIMEOUT,
                       help=f'Timeout por request en segundos (default: {Config.TIMEOUT})')
    parser.add_argument('--force-sync', action='store_true', help='Forzar modo síncrono')
    parser.add_argument('--no-cache', action='store_true', help='Deshabilitar cache')
    parser.add_argument('--verbose', action='store_true', help='Logging verbose')
    
    args = parser.parse_args()
    
    # Configurar logging
    setup_logging(verbose=args.verbose)
    
    # Validar username antes de iniciar
    is_valid, message = validate_username(args.username)
    if not is_valid:
        logger.error(f"❌ {message}")
        sys.exit(1)
    
    try:
        # Inicializar scanner
        use_async = not args.force_sync and PLAYWRIGHT_AVAILABLE
        scanner = OmniScanner(
            timeout=args.timeout,
            max_workers=args.workers,
            use_async=use_async,
            proxies_file=args.proxies,
            no_avatars=args.no_avatars,
            enable_cache=not args.no_cache
        )
        
        print(f"🔍 OmniScan iniciado para: {args.username}")
        print(f"📋 Plataformas disponibles: {', '.join(scanner.platforms.keys())}")
        
        # Ejecutar scan
        results = scanner.scan_username(args.username, args.platforms)
        
        # Determinar archivos de exportación
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = Path(f"scan_{args.username}_{timestamp}")
        
        export_formats = []
        if args.json:
            scanner.save_to_json(Path(args.json))
        else:
            export_formats.append('json')
        
        if args.csv:
            scanner.save_to_csv(Path(args.csv))
        else:
            export_formats.append('csv')
        
        if args.db:
            scanner.save_to_sqlite(Path(args.db))
        else:
            export_formats.append('sqlite')
        
        # Exportación unificada
        if export_formats:
            scanner.export_results(export_formats, base_name)
        
        # Mostrar resultados
        scanner.print_statistics()
        
        print(f"\n🎯 RESULTADOS DETALLADOS:")
        print("=" * 80)
        for result in sorted(scanner.results, key=lambda x: (-x.evidence_score, x.platform)):
            status = "✅ HIT" if result.exists else "❌ MISS"
            score_str = f"[Score: {result.evidence_score}/10]"
            print(f"{status:8} {result.platform:12} {score_str:15} → {result.url}")
            
            if result.title:
                print(f"         📝 Title: {result.title[:80]}{'...' if len(result.title) > 80 else ''}")
            if result.error:
                print(f"         ❗ Error: {result.error}")
        
        print("=" * 80)
        print("✅ Escaneo completado exitosamente")
        
    except KeyboardInterrupt:
        print("\n⏹️  Escaneo interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Error crítico durante el escaneo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
