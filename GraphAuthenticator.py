from msal import PublicClientApplication, SerializableTokenCache
import sys
from pathlib import Path

class GraphAuthenticator:
    def __init__(self):
        self.client_id = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft's well-known client ID
        self.scopes = ["https://graph.microsoft.com/.default"]
        
        # Set up cache file in user's home directory
        cache_dir = Path.home() / '.cache' / 'msgraph'
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = cache_dir / 'token_cache.bin'
        
        # Initialize token cache
        self.token_cache = SerializableTokenCache()
        if self.cache_file.exists():
            self.token_cache.deserialize(self.cache_file.read_text())
            
        self.app = PublicClientApplication(
            client_id=self.client_id,
            token_cache=self.token_cache
        )
        
    def _save_cache(self):
        """Save the token cache to file"""
        if self.token_cache.has_state_changed:
            self.cache_file.write_text(self.token_cache.serialize())
            
    def authenticate(self):
        """Attempts to get token from cache, falls back to device code flow"""
        print("\n🔐 Starting authentication process...")
        
        # Try to load token from cache first
        accounts = self.app.get_accounts()
        if accounts:
            print("\n📝 Found cached account, attempting silent authentication...")
            result = self.app.acquire_token_silent(self.scopes, account=accounts[0])
            if result:
                print("\n✅ Successfully retrieved token from cache!")
                self._save_cache()
                return result['access_token']
                
        print("\n🌐 No valid cached token found. Initiating device code flow...")
        flow = self.app.initiate_device_flow(scopes=self.scopes)
        
        if "user_code" not in flow:
            print("\n❌ Could not initiate device flow!")
            sys.exit(1)
            
        print("\n📱 Please use the following code to authenticate:")
        print("-" * 40)
        print(f"Code: {flow['user_code']}")
        print("-" * 40)
        print(f"\nGo to: {flow['verification_uri']}")
        print("\nWaiting for authentication...")
        
        result = self.app.acquire_token_by_device_flow(flow)
        
        if "access_token" in result:
            print("\n✅ Authentication successful!")
            
            if 'expires_in' in result:
                print(f"\nToken expires in: {result['expires_in']} seconds")
            
            # Save the cache after successful authentication
            self._save_cache()
            return result['access_token']
        else:
            print("\n❌ Authentication failed!")
            print(result.get("error"))
            print(result.get("error_description"))
            sys.exit(1)
