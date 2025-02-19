import logging
from typing import List, Dict

class DataProcessor:
    def __init__(self, storage):
        self.storage = storage
        self.logger = logging.getLogger(__name__)
    
    def get_new_tweets(self, current_tweets: List[Dict]) -> List[Dict]:
        """识别新增推文"""
        stored_ids = self.storage.get_processed_ids()
        current_ids = {t['id'] for t in current_tweets}
        new_ids = current_ids - stored_ids
        
        return [t for t in current_tweets if t['id'] in new_ids]
    
    def process_media(self, media_data: List[Dict]) -> List[str]:
        """处理媒体资源"""
        media_urls = []
        for media in media_data:
            if media['type'] == 'photo':
                media_urls.append(media['url'])
            elif media['type'] in ['video', 'animated_gif']:
                variants = media.get('variants', [])
                video = max(
                    [v for v in variants if v['content_type'] == 'video/mp4'],
                    key=lambda x: x.get('bit_rate', 0)
                )
                media_urls.append(video['url'])
        return media_urls[:4]  # 最多4个媒体