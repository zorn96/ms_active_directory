# Created in August 2021
#
# Author: Azaria Zornberg
#
# Copyright 2021 - 2021 Azaria Zornberg
#
# This file is part of ms_active_directory
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from enum import Enum


class ADRightsGuid(Enum):
    Abandon_Replication = 'ee914b82-0a98-11d1-adbb-00c04fd8d5cd'
    Add_GUID = '440820ad-65b4-11d1-a3da-0000f875ae0d'
    Allocate_Rids = '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd'
    Allowed_To_Authenticate = '68b1d179-0d15-4d4f-ab71-46152e79a7bc'
    Apply_Group_Policy = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
    Certificate_Enrollment = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    Certificate_AutoEnrollment = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    Change_Domain_Master = '014bf69c-7b3b-11d1-85f6-08002be74fab'
    Change_Infrastructure_Master = 'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd'
    Change_PDC = 'bae50096-4752-11d1-9052-00c04fc2d4cf'
    Change_Rid_Master = 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd'
    Change_Schema_Master = 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd'
    Create_Inbound_Forest_Trust = 'e2a36dc9-ae17-47c3-b58b-be34c55ba633'
    Do_Garbage_Collection = 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd'
    Domain_Administer_Server = 'ab721a52-1e2f-11d0-9819-00aa0040529b'
    DS_Check_Stale_Phantoms = '69ae6200-7f46-11d2-b9ad-00c04f79f805'
    DS_Execute_Intentions_Script = '2f16c4a5-b98e-432c-952a-cb388ba33f2e'
    DS_Install_Replica = '9923a32a-3607-11d2-b9be-0000f87a36b2'
    DS_Query_Self_Quota = '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc'
    DS_Replication_Get_Changes = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    DS_Replication_Get_Changes_All = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    DS_Replication_Get_Changes_In_Filtered_Set = '89e95b76-444d-4c62-991a-0facbeda640c'
    DS_Replication_Manage_Topology = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
    DS_Replication_Monitor_Topology = 'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96'
    DS_Replication_Synchronize = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
    Enable_Per_User_Reversibly_Encrypted_Password = '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5'
    Generate_RSoP_Logging = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
    Generate_RSoP_Planning = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
    Manage_Optional_Features = '7c0e2a7c-a419-48e4-a995-10180aad54dd'
    Migrate_SID_History = 'ba33815a-4f93-4c76-87f3-57574bff8109'
    msmq_Open_Connector = 'b4e60130-df3f-11d1-9c86-006008764d0e'
    msmq_Peek = '06bd3201-df3e-11d1-9c86-006008764d0e'
    msmq_Peek_computer_Journal = '4b6e08c3-df3c-11d1-9c86-006008764d0e'
    msmq_Peek_Dead_Letter = '4b6e08c1-df3c-11d1-9c86-006008764d0e'
    msmq_Receive = '06bd3200-df3e-11d1-9c86-006008764d0e'
    msmq_Receive_computer_Journal = '4b6e08c2-df3c-11d1-9c86-006008764d0e'
    msmq_Receive_Dead_Letter = '4b6e08c0-df3c-11d1-9c86-006008764d0e'
    msmq_Receive_journal = '06bd3203-df3e-11d1-9c86-006008764d0e'
    msmq_Send = '06bd3202-df3e-11d1-9c86-006008764d0e'
    Open_Address_Book = 'a1990816-4298-11d1-ade2-00c04fd8d5cd'
    Read_Only_Replication_Secret_Synchronization = '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'
    Reanimate_Tombstones = '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'
    Recalculate_Hierarchy = '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd'
    Recalculate_Security_Inheritance = '62dd28a8-7f46-11d2-b9ad-00c04f79f805'
    Receive_As = 'ab721a56-1e2f-11d0-9819-00aa0040529b'
    Refresh_Group_Cache = '9432c620-033c-4db7-8b58-14ef6d0bf477'
    Reload_SSL_Certificate = '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8'
    Run_Protect_Admin_Groups_Task = '7726b9d5-a4b4-4288-a6b2-dce952e80a7f'
    SAM_Enumerate_Entire_Domain = '91d67418-0135-4acc-8d79-c08e857cfbec'
    Send_As = 'ab721a54-1e2f-11d0-9819-00aa0040529b'
    Send_To = 'ab721a55-1e2f-11d0-9819-00aa0040529b'
    Unexpire_Password = 'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501'
    Update_Password_Not_Required_Bit = '280f369c-67c7-438e-ae98-1d46f3c6f541'
    Update_Schema_Cache = 'be2bb760-7f46-11d2-b9ad-00c04f79f805'
    User_Change_Password = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
    User_Force_Change_Password = '00299570-246d-11d0-a768-00aa006e0529'
    DS_Clone_Domain_Controller = '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e'
    DS_Read_Partition_Secrets = '084c93a2-620d-4879-a836-f0ae47de0e89'
    DS_Write_Partition_Secrets = '94825a8d-b171-4116-8146-1e34d8f54401'
    DS_Set_Owner = '4125c71f-7fac-4ff0-bcb7-f09a41325286'
    DS_Bypass_Quota = '88a9933e-e5c8-4f2a-9dd7-2527416b8092'
    DS_Validated_Write_Computer = '9b026da6-0d3c-465c-8bee-5199d7165cba'
