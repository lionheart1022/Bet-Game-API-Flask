from datetime import datetime
import math
from sqlalchemy import sql
from sqlalchemy.sql.expression import func
import sqlalchemy

from .main import db
import config

def fast_count(query):
    """
    Get count of queried items avoiding using subquery (like query.count() does)
    """
    count_query = query.statement.with_only_columns([func.count()]).order_by(None)
    return query.session.execute(count_query).scalar()
