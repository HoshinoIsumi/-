import json
import time
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from sqlalchemy import create_engine, Column, Integer, String, Text, Date
from sqlalchemy.orm import sessionmaker, declarative_base  # 更新这一行


def fetch_page_content(url, max_retries=5, backoff_factor=0.5):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    session = requests.Session()
    retry = Retry(total=max_retries, backoff_factor=backoff_factor, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    for attempt in range(max_retries):
        try:
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 404:
                print(f"404 error for {url}, skipping this link.")
                return None
            print(f"Attempt {attempt + 1} failed: {e}")
            if "SSLError" in str(e) or "Max retries exceeded" in str(e):
                print("SSL error encountered. Waiting for 30 s before retrying...")
                time.sleep(30)  # 等待后再重试
            if attempt + 1 == max_retries:
                raise
            time.sleep(backoff_factor * (2 ** attempt))


def parse_content(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    data = {}

    fonts = soup.find_all('font')
    for i, font in enumerate(fonts):
        text = font.get_text(strip=True)
        if "Virus Name" in text:
            data['病毒名称'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Aliases" in text:
            data['别名'] = fonts[i + 1].get_text(strip=True).replace('\n', ', ') if i + 1 < len(fonts) else ""
        elif "Discovery Date" in text:
            data['发现日期'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Origin" in text:
            data['来源'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Length" in text:
            data['长度'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Type" in text:
            data['类型'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "SubType" in text:
            data['子类型'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Risk Assessment" in text:
            data['风险评估'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Minimum Engine" in text:
            data['最低引擎'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Minimum Dat" in text:
            data['最低数据'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "DAT Release Date" in text:
            data['DAT 发布日期'] = fonts[i + 1].get_text(strip=True) if i + 1 < len(fonts) else ""
        elif "Virus Characteristics" in text:
            data['病毒特征'] = fonts[i + 1].get_text(strip=True).replace('\n', ' ') if i + 1 < len(fonts) else ""
        elif "Symptoms" in text:
            data['症状'] = fonts[i + 1].get_text(strip=True).replace('\n', ' ') if i + 1 < len(fonts) else ""
        elif "Method Of Infection" in text:
            data['感染方式'] = fonts[i + 1].get_text(strip=True).replace('\n', ' ') if i + 1 < len(fonts) else ""
        elif "Removal Instructions" in text:
            data['移除指令'] = fonts[i + 1].get_text(strip=True).replace('\n', ' ') if i + 1 < len(fonts) else ""

            # 特别处理病毒名称
            virus_name_element = soup.find(string="Virus Name")
            if virus_name_element:
                data['病毒名称'] = virus_name_element.find_next('br').next_sibling.strip()

            return data
    return data


def extract_virus_links(url):
    html_content = fetch_page_content(url)
    if html_content is None:  # 确保 HTML 内容有效
        return []
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []

    for a_tag in soup.find_all('a', href=True):
        if 'virus_k' in a_tag['href']:
            full_url = urljoin(url, a_tag['href'])
            links.append(full_url)

    return links


def append_to_json_file(data, filename='all_virus_info.json'):
    with open(filename, 'a', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False)
        file.write('\n')

# SQLAlchemy 基础类
Base = declarative_base()

# 定义病毒信息模型
class VirusInfo(Base):
    __tablename__ = 'virus_info'

    id = Column(Integer, primary_key=True, autoincrement=True)
    virus_name = Column(String(255))
    aliases = Column(Text)
    discovery_date = Column(Date)
    origin = Column(String(255))
    length = Column(String(255))
    type = Column(String(255))
    subtype = Column(String(255))
    risk_assessment = Column(String(255))
    minimum_engine = Column(String(255))
    minimum_dat = Column(String(255))
    dat_release_date = Column(Date)
    virus_characteristics = Column(Text)
    symptoms = Column(Text)
    method_of_infection = Column(Text)
    removal_instructions = Column(Text)

# 创建数据库连接和表
engine = create_engine('mysql+mysqlconnector://virus_user:isumi@localhost/virus_db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


def parse_date(date_str):
    """改进日期解析函数，增加对更多日期格式的处理"""
    if not date_str or not isinstance(date_str, str):
        return None  # 如果是空字符串，返回 None
    # 支持的日期格式
    date_formats = [
        '%m/%d/%y',  # MM/DD/YY
        '%m/%d/%Y',  # MM/DD/YYYY
        '%Y-%m-%d',  # YYYY-MM-DD
        '%y-%m-%d'   # YY-MM-DD
    ]
    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue
    print(f"无法解析的日期格式: {date_str}")
    return None


def clean_data(data):
    """清洗数据，包括日期字段的格式化"""
    cleaned_data = data.copy()

    # 将日期字段进行标准化处理
    for date_field in ['发现日期', 'DAT 发布日期']:
        if date_field in cleaned_data and cleaned_data[date_field]:
            cleaned_data[date_field] = parse_date(cleaned_data[date_field])

    return cleaned_data

def format_date(date_str):
    if date_str:
        try:
            # 尝试 MM/DD/YYYY 格式
            return datetime.strptime(date_str, '%m/%d/%Y').date()
        except ValueError:
            try:
                # 尝试 MM/DD/YY 格式
                return datetime.strptime(date_str, '%m/%d/%y').date()
            except ValueError:
                try:
                    # 尝试 M/D/YYYY 格式
                    return datetime.strptime(date_str, '%-m/%-d/%Y').date()
                except ValueError:
                    try:
                        # 尝试 M/D/YY 格式
                        return datetime.strptime(date_str, '%-m/%-d/%y').date()
                    except ValueError:
                        print(f"日期格式错误: {date_str}")
                        return None
    return None


def insert_virus_data(data, session):
    # 调试打印，检查 data 是否正确
    print("正在插入的数据内容：")
    for key, value in data.items():
        print(f"{key}: {value}")

    try:
        dat_release_date = format_date(data.get('DAT 发布日期'))

        discovery_date = format_date(data.get('发现日期'))  # 确保使用正确的键来获取数据

        new_virus = VirusInfo(
            virus_name=data.get('病毒名称'),
            aliases=data.get('别名'),
            discovery_date=discovery_date,
            origin=data.get('来源'),
            length=data.get('长度'),
            type=data.get('类型'),
            subtype=data.get('子类型'),
            risk_assessment=data.get('风险评估'),
            minimum_engine=data.get('最低引擎'),
            minimum_dat=data.get('最低数据'),
            dat_release_date=dat_release_date,
            virus_characteristics=data.get('病毒特征'),
            symptoms=data.get('症状'),
            method_of_infection=data.get('感染方式'),
            removal_instructions=data.get('移除指令')
        )

        session.add(new_virus)
        session.commit()
        print(f"数据插入成功：{data.get('病毒名称')}")

    except Exception as e:
        print(f"数据插入失败: {data.get('病毒名称')}, 错误信息: {e}")
        session.rollback()  # 发生错误时回滚事务

def process_virus_page(url):
    print(f"正在处理页面: {url}")
    html_content = fetch_page_content(url)
    if html_content is None:
        print(f"无法访问页面: {url}, 已跳过。")
        return  # 跳过无效页面

    data = parse_content(html_content)
    if data:
        insert_virus_data(data, session)  # 实时插入数据
        append_to_json_file(data)
        print(f"成功插入数据: {data.get('病毒名称', '未知病毒')}")
    else:
        print(f"解析失败或数据为空: {url}")



def main(start_url):
    global session
    session = Session()

    visited_links = set()
    try:
        with open('visited_links.txt', 'r', encoding='utf-8') as file:
            visited_links = set(line.strip() for line in file)
    except FileNotFoundError:
        print("visited_links.txt 文件未找到，将从头开始。")

    virus_links = extract_virus_links(start_url)
    for link in virus_links:
        if link not in visited_links:
            process_virus_page(link)
            visited_links.add(link)
            with open('visited_links.txt', 'a', encoding='utf-8') as file:
                file.write(link + '\n')

if __name__ == '__main__':
    start_urls = [
        'https://web.archive.org/web/20001210063100/http://vil.nai.com/villib/alphar.asp?char=a',
        'https://web.archive.org/web/20001210063100/http://vil.nai.com/villib/alphar.asp?char=b',
        'https://web.archive.org/web/20001210063100/http://vil.nai.com/villib/alphar.asp?char=c',
        'https://web.archive.org/web/20001210063100/http://vil.nai.com/villib/alphar.asp?char=d',
        'https://web.archive.org/web/20001210063100/http://vil.nai.com/villib/alphar.asp?char=e',
        'https://web.archive.org/web/20001210063100/http://vil.nai.com/villib/alphar.asp?char=f',
        'https://web.archive.org/web/20001210120100/http://vil.nai.com/villib/alphar.asp?char=g',
        'https://web.archive.org/web/20001210125700/http://vil.nai.com/villib/alphar.asp?char=h',
        'https://web.archive.org/web/20001210144700/http://vil.nai.com/villib/alphar.asp?char=i',
        'https://web.archive.org/web/20001210153900/http://vil.nai.com/villib/alphar.asp?char=j',
        'https://web.archive.org/web/20001210163300/http://vil.nai.com/villib/alphar.asp?char=k',
        'https://web.archive.org/web/20001210173600/http://vil.nai.com/villib/alphar.asp?char=l',
        'https://web.archive.org/web/20001210183100/http://vil.nai.com/villib/alphar.asp?char=m',
        'https://web.archive.org/web/20001210192700/http://vil.nai.com/villib/alphar.asp?char=n',
        'https://web.archive.org/web/20001210202000/http://vil.nai.com/villib/alphar.asp?char=o',
        'https://web.archive.org/web/20011106231228/http://vil.nai.com/villib/alphar.asp?char=p',
        'https://web.archive.org/web/20000930015653/http://vil.nai.com/villib/alphar.asp?char=q',
        'https://web.archive.org/web/20001210232300/http://vil.nai.com/villib/alphar.asp?char=r',
        'https://web.archive.org/web/20001211013300/http://vil.nai.com/villib/alphar.asp?char=s',
        'https://web.archive.org/web/20001211023700/http://vil.nai.com/villib/alphar.asp?char=t',
        'https://web.archive.org/web/20000623062035/http://vil.nai.com/villib/alphar.asp?char=u',
        'https://web.archive.org/web/20001211042000/http://vil.nai.com/villib/alphar.asp?char=v',
        'https://web.archive.org/web/20001211052000/http://vil.nai.com/villib/alphar.asp?char=w',
        'https://web.archive.org/web/20001211074400/http://vil.nai.com/villib/alphar.asp?char=x',
        'https://web.archive.org/web/20000623120552/http://vil.nai.com/villib/alphar.asp?char=y',
        'https://web.archive.org/web/20000930095509/http://vil.nai.com/villib/alphar.asp?char=z',
        # 在此添加更多链接
    ]

    for start_url in start_urls:
        main(start_url)
