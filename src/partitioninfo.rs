use std::fs::File;
use std::io::Read;
use std::fmt;

// Info in the first 512 Bytes of the partition
#[derive(Default, Debug, Clone, Copy)]
pub struct PartitionInfo {
    pub bytes_per_sector: u16,
    pub sectors_in_cluster: u8 ,
    pub total_sectors_in_partition: u64,
    // Unsued for now
    pub cluster_containing_mft: u64
}

impl fmt::Display for PartitionInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PartitionInfo {{\n\
                   \tbytes_per_sector: {},\n\
                   \tsectors_in_cluster: {}\n\
                   \ttotal_sectors_in_partition: {},\n\
                   \tcluster_containing_mft: {},\n\
                   }}",
               self.bytes_per_sector,
               self.sectors_in_cluster,
               self.total_sectors_in_partition,
               self.cluster_containing_mft)
    }
}

pub fn read_info_ntfs(partition: &mut File) -> Result<PartitionInfo, &'static str> {
        let mut buffer = [0u8; 512];
        if partition.read(&mut buffer).expect("Reading first sector of partition failed.") != 512 {
            return Err("Failed to read the full first 512 Bytes of partition. Bytes missing.")
        }
        let buffer_ptr = &buffer as *const _;
        
        let mut info = PartitionInfo::default();
        unsafe {
            let filesystem_identifier: u64 = *((buffer_ptr as u64 + 0x03) as *const u64);
            if filesystem_identifier != 0x202020205346544E {
                return Err("Filesystem is not NTFS.");
            }

            info.bytes_per_sector = *((buffer_ptr as u64 + 0x0B) as *const u16);
            info.sectors_in_cluster = *((buffer_ptr as u64 + 0x0D) as *const u8);
            info.total_sectors_in_partition = *((buffer_ptr as u64 + 0x28) as *const u64);
            info.cluster_containing_mft = *((buffer_ptr as u64 + 0x30) as *const u64);
        }

        Ok(info)
    }
