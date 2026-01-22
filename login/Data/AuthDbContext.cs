using login.Models;
using Microsoft.EntityFrameworkCore;

namespace login.Data
{
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }
        public DbSet<Refreshtoken> RefreshTokens { get; set; }
        public DbSet<User> Users { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Username).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
                entity.Property(e => e.PasswordHash).IsRequired().HasMaxLength(256);
                entity.Property(e => e.Role).IsRequired().HasMaxLength(20).HasDefaultValue("User");
                entity.Property(e => e.IsEmailConfirmed).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.IsActive).IsRequired();
                entity.HasIndex(e => e.Username).IsUnique();
                entity.HasIndex(e => e.Email).IsUnique();

                entity.HasMany(e => e.RefreshTokens)
                      .WithOne()  
                      .HasForeignKey(rt => rt.UserId)
                      .HasPrincipalKey(u => u.Username);


            });
            modelBuilder.Entity<Refreshtoken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Token).IsRequired().HasMaxLength(500);
                entity.Property(e => e.UserId).IsRequired().HasMaxLength(50);
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.ExpiresAt).IsRequired();
                entity.HasIndex(e => e.Token);
                entity.HasIndex(e => e.UserId);

            });
            // Birinchi Admin foydalanuvchini qo'lda qo'shish
            modelBuilder.Entity<User>().HasData(
                new User
                {
                    Id = 1,
                    Username = "admin",
                    Email = "Admin@gmail.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin123!"),
                    Role = "Admin",
                    IsEmailConfirmed = true,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                });
            modelBuilder.Entity<User>().HasData(
                new User
                {
                    Id = 2,
                    Username = "odam",
                    Email = "odam@gmail.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"),
                    Role = "User",
                    IsEmailConfirmed = true,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                });
        }
    }

}

