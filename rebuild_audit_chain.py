"""Rebuild audit log chain hashes and signatures"""
from app import create_app
from app.models import db, AuditLog
from app.security import AuditLogger

app = create_app()
with app.app_context():
    logs = AuditLog.query.order_by(AuditLog.id).all()
    
    print(f"Rebuilding chain for {len(logs)} logs...")
    
    previous_hash = None
    for i, log in enumerate(logs):
        # Recompute entry hash
        entry_hash = AuditLogger.compute_entry_hash({
            'timestamp': log.timestamp.isoformat(),
            'user_id': log.user_id,
            'action': log.action,
            'resource_id': log.resource_id
        })
        
        # Recompute signature
        signature = AuditLogger.sign_entry(entry_hash, previous_hash)
        
        # Update log
        log.entry_hash = entry_hash
        log.previous_hash = previous_hash
        log.signature = signature
        
        print(f"  Log {log.id}: Hash updated, previous_hash={'None' if previous_hash is None else previous_hash[:16]+'...'}")
        
        # Set previous_hash for next iteration
        previous_hash = entry_hash
    
    db.session.commit()
    print(f"\n✅ Chain rebuilt successfully!")
    
    # Verify
    is_valid, broken_at = AuditLogger.verify_log_chain(logs)
    print(f"✅ Chain verification: {'PASSED' if is_valid else f'FAILED at index {broken_at}'}")
