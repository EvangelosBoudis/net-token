using Application.Repository;

namespace Infrastructure.Store.Repository;

public class RepositoryBase<TEntity> : IRepositoryBase<TEntity> where TEntity : class
{
    protected readonly DataContext Context;

    protected RepositoryBase(DataContext context)
    {
        Context = context;
    }

    public async Task SaveAsync(TEntity entity)
    {
        await Context.AddAsync(entity);
    }

    private async Task FlushAsync()
    {
        await Context.SaveChangesAsync();
    }

    public async Task SaveAndFlushAsync(TEntity entity)
    {
        await SaveAsync(entity);
        await FlushAsync();
    }
}