"""
Reset Database - Delete all audit logs and elections
Use this for a fresh start
"""
from app import create_app
from app.models import db, AuditLog, Election, Vote, Candidate

def reset_database():
    app = create_app()
    with app.app_context():
        try:
            # Delete all votes first (foreign key constraint)
            votes_count = Vote.query.count()
            Vote.query.delete()
            
            # Delete all candidates
            candidates_count = Candidate.query.count()
            Candidate.query.delete()
            
            # Delete all elections
            elections_count = Election.query.count()
            Election.query.delete()
            
            # Delete all audit logs
            logs_count = AuditLog.query.count()
            AuditLog.query.delete()
            
            # Commit all deletions
            db.session.commit()
            
            print("✅ Database reset successful!")
            print(f"   - Deleted {votes_count} votes")
            print(f"   - Deleted {candidates_count} candidates")
            print(f"   - Deleted {elections_count} elections")
            print(f"   - Deleted {logs_count} audit logs")
            print("\n🎉 Fresh start ready! Users are preserved.")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error resetting database: {e}")

if __name__ == '__main__':
    reset_database()
