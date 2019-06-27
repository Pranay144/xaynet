import os

from .config import get_config

# Prepare dataset directory by creating it
# in case it does not exist
local_datasets_dir = get_config("local_datasets_dir")

if "~" in local_datasets_dir:
    local_datasets_dir = os.path.expanduser(local_datasets_dir)

local_datasets_dir = os.path.abspath(local_datasets_dir)

if not os.path.isdir(local_datasets_dir):
    os.makedirs(local_datasets_dir)
