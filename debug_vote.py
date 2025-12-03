"""Debug script to investigate vote decryption issue"""
from app import create_app
from app.models import Vote, ElectionKeyPair
import base64

app = create_app()
with app.app_context():
    vote = Vote.query.order_by(Vote.id.desc()).first()
    if vote:
        print('=== Vote Data ===')
        print(f'Vote ID: {vote.id}')
        print(f'Election ID: {vote.election_id}')
        print(f'Encryption Version: {vote.encryption_version}')
        print(f'Is Hybrid: {vote.is_hybrid_encrypted()}')
        print()
        print(f'encrypted_vote length: {len(vote.encrypted_vote) if vote.encrypted_vote else 0}')
        print(f'encrypted_vote: {repr(vote.encrypted_vote[:100]) if vote.encrypted_vote and len(vote.encrypted_vote) > 100 else repr(vote.encrypted_vote)}')
        print()
        print(f'encrypted_key: {repr(vote.encrypted_key[:100]) if vote.encrypted_key and len(vote.encrypted_key) > 100 else repr(vote.encrypted_key)}')
        print()
        print(f'vote_nonce: {repr(vote.vote_nonce)}')
        print()
        print(f'vote_tag: {repr(vote.vote_tag)}')
        
        # Check keypair
        keypair = ElectionKeyPair.query.filter_by(election_id=vote.election_id).first()
        print(f'\nKeypair exists: {keypair is not None}')
        
        # Try base64 decode
        print('\n=== Base64 Decode Test ===')
        if vote.encrypted_vote:
            try:
                decoded = base64.b64decode(vote.encrypted_vote)
                print(f'encrypted_vote decode: OK, {len(decoded)} bytes')
            except Exception as e:
                print(f'encrypted_vote decode ERROR: {e}')
        
        if vote.encrypted_key:
            try:
                decoded = base64.b64decode(vote.encrypted_key)
                print(f'encrypted_key decode: OK, {len(decoded)} bytes')
            except Exception as e:
                print(f'encrypted_key decode ERROR: {e}')
        
        if vote.vote_nonce:
            try:
                decoded = base64.b64decode(vote.vote_nonce)
                print(f'vote_nonce decode: OK, {len(decoded)} bytes')
            except Exception as e:
                print(f'vote_nonce decode ERROR: {e}')
        
        # Try full decryption
        print('\n=== Full Decryption Test ===')
        if vote.is_hybrid_encrypted() and keypair:
            try:
                from app.crypto_utils import CryptoUtils
                private_key = keypair.get_private_key()
                print(f'Private key retrieved: {len(private_key)} chars')
                
                decrypted = CryptoUtils.decrypt_hybrid_vote(
                    vote.encrypted_vote,
                    vote.encrypted_key,
                    vote.vote_nonce,
                    private_key
                )
                print(f'DECRYPTED DATA: {decrypted}')
            except Exception as e:
                import traceback
                print(f'DECRYPTION ERROR: {e}')
                traceback.print_exc()
    else:
        print('No votes found in database')
