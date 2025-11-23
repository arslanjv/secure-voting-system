"""
Database Initialization Script
Creates tables and optionally loads sample data
"""
from app import create_app
from app.models import db, User, Election, Candidate, UserRole, ElectionStatus
from app.security import PasswordManager
from datetime import datetime, timedelta
import sys


def init_database(with_sample_data=False):
    """Initialize database with optional sample data"""
    app = create_app()
    
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("✓ Database tables created successfully")
        
        if with_sample_data:
            print("\nCreating sample data...")
            
            # Create admin user
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@securevote.com',
                    password_hash=PasswordManager.hash_password('SecureAdmin2024!'),
                    role=UserRole.ADMINISTRATOR,
                    is_active=True
                )
                db.session.add(admin)
                print("✓ Admin user created (username: admin, password: SecureAdmin2024!)")
            
            # Create auditor user
            auditor = User.query.filter_by(username='auditor').first()
            if not auditor:
                auditor = User(
                    username='auditor',
                    email='auditor@securevote.com',
                    password_hash=PasswordManager.hash_password('SecureAuditor2024!'),
                    role=UserRole.AUDITOR,
                    is_active=True
                )
                db.session.add(auditor)
                print("✓ Auditor user created (username: auditor, password: SecureAuditor2024!)")
            
            # Create test voter users
            for i in range(1, 4):
                username = f'voter{i}'
                if not User.query.filter_by(username=username).first():
                    user = User(
                        username=username,
                        email=f'voter{i}@example.com',
                        password_hash=PasswordManager.hash_password(f'VoterPass{i}2024!'),
                        role=UserRole.VOTER,
                        is_active=True
                    )
                    db.session.add(user)
                    print(f"✓ Voter user created (username: {username}, password: VoterPass{i}2024!)")
            
            db.session.commit()
            
            # Create sample election
            election = Election.query.filter_by(title='Sample Election').first()
            if not election:
                election = Election(
                    title='Sample Election - Student Council President',
                    description='Vote for your next student council president. This is a sample election to demonstrate the voting system.',
                    start_time=datetime.utcnow(),
                    end_time=datetime.utcnow() + timedelta(days=7),
                    status=ElectionStatus.ACTIVE,
                    max_selections=1,
                    allow_multiple_votes=False,
                    created_by=admin.id
                )
                db.session.add(election)
                db.session.commit()
                print(f"✓ Sample election created: {election.title}")
                
                # Add candidates
                candidates_data = [
                    {
                        'name': 'Alice Johnson',
                        'description': 'Focus on student welfare and campus improvements.',
                        'order': 1
                    },
                    {
                        'name': 'Bob Smith',
                        'description': 'Committed to enhancing academic resources and facilities.',
                        'order': 2
                    },
                    {
                        'name': 'Carol Williams',
                        'description': 'Dedicated to promoting diversity and inclusion on campus.',
                        'order': 3
                    }
                ]
                
                for candidate_data in candidates_data:
                    candidate = Candidate(
                        election_id=election.id,
                        name=candidate_data['name'],
                        description=candidate_data['description'],
                        order=candidate_data['order']
                    )
                    db.session.add(candidate)
                    print(f"  ✓ Candidate added: {candidate.name}")
                
                db.session.commit()
            
            print("\n" + "="*60)
            print("Sample Data Summary")
            print("="*60)
            print("\nUsers created:")
            print("  Admin:    username='admin',    password='SecureAdmin2024!'")
            print("  Auditor:  username='auditor',  password='SecureAuditor2024!'")
            print("  Voter 1:  username='voter1',   password='VoterPass12024!'")
            print("  Voter 2:  username='voter2',   password='VoterPass22024!'")
            print("  Voter 3:  username='voter3',   password='VoterPass32024!'")
            print("\nSample Election:")
            print(f"  Title: {election.title}")
            print(f"  Status: {election.status.value}")
            print(f"  Candidates: {election.candidates.count()}")
            print("\n" + "="*60)
            print("\nYou can now login and test the voting system!")
            print("="*60)


if __name__ == '__main__':
    # Check command line arguments
    with_sample = '--with-sample-data' in sys.argv or '-s' in sys.argv
    
    print("="*60)
    print("Secure Voting System - Database Initialization")
    print("="*60)
    
    try:
        init_database(with_sample_data=with_sample)
        print("\n✓ Database initialization completed successfully!")
    except Exception as e:
        print(f"\n✗ Error initializing database: {str(e)}")
        sys.exit(1)
