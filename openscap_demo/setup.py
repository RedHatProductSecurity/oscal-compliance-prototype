from distutils.core import setup


setup(
  name='complytime',
  version='0.0.1',
  packages=['complytime'],
  entry_points={
    'console_scripts': ['complytime=complytime.__main__:init']
  }
)
