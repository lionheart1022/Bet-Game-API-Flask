from flask import redirect, url_for, request, session

from flask_admin import Admin, BaseView, expose
from flask.ext.basicauth import BasicAuth
from flask.ext.login import LoginManager, login_user, current_user, logout_user

from sqlalchemy.orm.exc import NoResultFound

admin = Admin(name='admin', template_mode='bootstrap3')
login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    from .models import Player  # avoiding cyclic reference =(
    try:
        return Player.query.get(user_id)
    except NoResultFound:
        return None


def init(app):
    admin.init_app(app)
    login_manager.init_app(app)


class LoginView(BaseView):
    def is_visible(self):
        return not current_user.is_authenticated

    @expose('/', methods=('GET', 'POST'))
    def index(self):
        from .models import Player  # avoiding cyclic reference =(
        from .helpers import check_password

        if request.form and 'login' in request.form and 'password' in request.form:
            user = Player.find(request.form['login'])
            if user and check_password(request.form['password'], user.password) and login_user(user):
                return redirect(url_for('admin.index'))
        return self.render('admin/login.html')


class AdminView(BaseView):
    def is_visible(self):
        return current_user.is_authenticated and current_user.is_active

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_active

class LogoutView(AdminView):
    @expose('/')
    def index(self):
        logout_user()
        return redirect(url_for('admin.index'))

admin.add_view(LoginView(name='Login', endpoint='login'))
admin.add_view(LogoutView(name='Logout', endpoint='logout'))



